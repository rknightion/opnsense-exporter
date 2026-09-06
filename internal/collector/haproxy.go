package collector

import (
	"context"
	"log/slog"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

type haproxyCollector struct {
	log *slog.Logger

	serviceRunning    *prometheus.Desc
	procUptime        *prometheus.Desc
	procCurrConns     *prometheus.Desc
	procConnsTotal    *prometheus.Desc
	procRequestsTotal *prometheus.Desc
	procIdlePercent   *prometheus.Desc
	frontendStatus    *prometheus.Desc
	frontendCurrSess  *prometheus.Desc
	frontendSessTotal *prometheus.Desc
	frontendBytesIn   *prometheus.Desc
	frontendBytesOut  *prometheus.Desc
	frontendReqErrors *prometheus.Desc
	frontendReqDenied *prometheus.Desc
	frontendResponses *prometheus.Desc
	backendStatus     *prometheus.Desc
	backendCurrSess   *prometheus.Desc
	backendSessTotal  *prometheus.Desc
	backendBytesIn    *prometheus.Desc
	backendBytesOut   *prometheus.Desc
	backendQueue      *prometheus.Desc
	backendConnErrors *prometheus.Desc
	backendRespErrors *prometheus.Desc
	backendRetries    *prometheus.Desc
	backendRedispatch *prometheus.Desc
	backendActiveSrv  *prometheus.Desc
	backendBackupSrv  *prometheus.Desc
	backendResponses  *prometheus.Desc
	serverStatus      *prometheus.Desc
	serverMaintenance *prometheus.Desc
	serverCurrSess    *prometheus.Desc
	serverSessTotal   *prometheus.Desc
	serverBytesIn     *prometheus.Desc
	serverBytesOut    *prometheus.Desc
	serverQueue       *prometheus.Desc
	serverConnErrors  *prometheus.Desc
	serverRespErrors  *prometheus.Desc
	serverCheckFail   *prometheus.Desc
	serverDowntime    *prometheus.Desc
	serverWeight      *prometheus.Desc

	// Added for #201 (stick-table occupancy + show-stat latency/health-
	// transition/capacity fields).
	connectionLimit       *prometheus.Desc
	sslCurrentConnections *prometheus.Desc
	frontendRequestsTotal *prometheus.Desc
	frontendSessionLimit  *prometheus.Desc
	backendQueueTimeAvg   *prometheus.Desc
	backendConnectTimeAvg *prometheus.Desc
	backendRespTimeAvg    *prometheus.Desc
	backendTotalTimeAvg   *prometheus.Desc
	backendSelectedTotal  *prometheus.Desc
	backendAbortsTotal    *prometheus.Desc
	serverQueueTimeAvg    *prometheus.Desc
	serverConnectTimeAvg  *prometheus.Desc
	serverRespTimeAvg     *prometheus.Desc
	serverTotalTimeAvg    *prometheus.Desc
	serverCheckDowns      *prometheus.Desc
	serverLastStateChange *prometheus.Desc
	stickTableSize        *prometheus.Desc
	stickTableUsed        *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &haproxyCollector{
		subsystem: HAProxySubsystem,
	})
}

func (c *haproxyCollector) Name() string { return c.subsystem }

func (c *haproxyCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	feLabels := []string{"frontend"}
	beLabels := []string{"backend"}
	srvLabels := []string{"backend", "server"}

	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the HAProxy service is running (1 = running, 0 = stopped/disabled)", nil)
	c.procUptime = buildPrometheusDesc(c.subsystem, "process_uptime_seconds",
		"HAProxy process uptime in seconds", nil)
	c.procCurrConns = buildPrometheusDesc(c.subsystem, "process_current_connections",
		"Current number of connections on the HAProxy process", nil)
	c.procConnsTotal = buildPrometheusDesc(c.subsystem, "process_connections_total",
		"Cumulative connections accepted by the HAProxy process", nil)
	c.procRequestsTotal = buildPrometheusDesc(c.subsystem, "process_requests_total",
		"Cumulative HTTP requests processed by the HAProxy process", nil)
	c.procIdlePercent = buildPrometheusDesc(c.subsystem, "process_idle_time_percent",
		"HAProxy process idle time percentage", nil)

	c.frontendStatus = buildPrometheusDesc(c.subsystem, "frontend_status",
		"HAProxy frontend status (1 = OPEN, 0 = otherwise)", feLabels)
	c.frontendCurrSess = buildPrometheusDesc(c.subsystem, "frontend_current_sessions",
		"Current sessions on this frontend", feLabels)
	c.frontendSessTotal = buildPrometheusDesc(c.subsystem, "frontend_sessions_total",
		"Cumulative sessions on this frontend", feLabels)
	c.frontendBytesIn = buildPrometheusDesc(c.subsystem, "frontend_bytes_in_total",
		"Cumulative bytes received by this frontend", feLabels)
	c.frontendBytesOut = buildPrometheusDesc(c.subsystem, "frontend_bytes_out_total",
		"Cumulative bytes sent by this frontend", feLabels)
	c.frontendReqErrors = buildPrometheusDesc(c.subsystem, "frontend_request_errors_total",
		"Cumulative request errors on this frontend", feLabels)
	c.frontendReqDenied = buildPrometheusDesc(c.subsystem, "frontend_requests_denied_total",
		"Cumulative requests denied by security rules on this frontend", feLabels)
	c.frontendResponses = buildPrometheusDesc(c.subsystem, "frontend_http_responses_total",
		"Cumulative HTTP responses by status code class on this frontend",
		[]string{"frontend", "code"})

	c.backendStatus = buildPrometheusDesc(c.subsystem, "backend_status",
		"HAProxy backend status (1 = UP, 0 = otherwise)", beLabels)
	c.backendCurrSess = buildPrometheusDesc(c.subsystem, "backend_current_sessions",
		"Current sessions on this backend", beLabels)
	c.backendSessTotal = buildPrometheusDesc(c.subsystem, "backend_sessions_total",
		"Cumulative sessions on this backend", beLabels)
	c.backendBytesIn = buildPrometheusDesc(c.subsystem, "backend_bytes_in_total",
		"Cumulative bytes received by this backend", beLabels)
	c.backendBytesOut = buildPrometheusDesc(c.subsystem, "backend_bytes_out_total",
		"Cumulative bytes sent by this backend", beLabels)
	c.backendQueue = buildPrometheusDesc(c.subsystem, "backend_queue_current",
		"Current requests queued on this backend", beLabels)
	c.backendConnErrors = buildPrometheusDesc(c.subsystem, "backend_connection_errors_total",
		"Cumulative connection errors on this backend", beLabels)
	c.backendRespErrors = buildPrometheusDesc(c.subsystem, "backend_response_errors_total",
		"Cumulative response errors on this backend", beLabels)
	c.backendRetries = buildPrometheusDesc(c.subsystem, "backend_retries_total",
		"Cumulative connection retries on this backend", beLabels)
	c.backendRedispatch = buildPrometheusDesc(c.subsystem, "backend_redispatches_total",
		"Cumulative request redispatches on this backend", beLabels)
	c.backendActiveSrv = buildPrometheusDesc(c.subsystem, "backend_active_servers",
		"Number of active servers on this backend", beLabels)
	c.backendBackupSrv = buildPrometheusDesc(c.subsystem, "backend_backup_servers",
		"Number of backup servers on this backend", beLabels)
	c.backendResponses = buildPrometheusDesc(c.subsystem, "backend_http_responses_total",
		"Cumulative HTTP responses by status code class on this backend",
		[]string{"backend", "code"})

	c.serverStatus = buildPrometheusDesc(c.subsystem, "server_status",
		"HAProxy server status (1 = UP, 0 = otherwise)", srvLabels)
	c.serverMaintenance = buildPrometheusDesc(c.subsystem, "server_maintenance",
		"Whether this HAProxy server is in maintenance (1 = status begins with MAINT, 0 = otherwise)", srvLabels)
	c.serverCurrSess = buildPrometheusDesc(c.subsystem, "server_current_sessions",
		"Current sessions on this server", srvLabels)
	c.serverSessTotal = buildPrometheusDesc(c.subsystem, "server_sessions_total",
		"Cumulative sessions on this server", srvLabels)
	c.serverBytesIn = buildPrometheusDesc(c.subsystem, "server_bytes_in_total",
		"Cumulative bytes received by this server", srvLabels)
	c.serverBytesOut = buildPrometheusDesc(c.subsystem, "server_bytes_out_total",
		"Cumulative bytes sent by this server", srvLabels)
	c.serverQueue = buildPrometheusDesc(c.subsystem, "server_queue_current",
		"Current requests queued on this server", srvLabels)
	c.serverConnErrors = buildPrometheusDesc(c.subsystem, "server_connection_errors_total",
		"Cumulative connection errors on this server", srvLabels)
	c.serverRespErrors = buildPrometheusDesc(c.subsystem, "server_response_errors_total",
		"Cumulative response errors on this server", srvLabels)
	c.serverCheckFail = buildPrometheusDesc(c.subsystem, "server_check_failures_total",
		"Cumulative failed health checks on this server", srvLabels)
	c.serverDowntime = buildPrometheusDesc(c.subsystem, "server_downtime_seconds_total",
		"Cumulative downtime of this server in seconds", srvLabels)
	c.serverWeight = buildPrometheusDesc(c.subsystem, "server_weight",
		"Current effective weight of this server", srvLabels)

	// #201: process-level capacity.
	c.connectionLimit = buildPrometheusDesc(c.subsystem, "connection_limit",
		"HAProxy process-wide connection limit (Maxconn)", nil)
	c.sslCurrentConnections = buildPrometheusDesc(c.subsystem, "ssl_current_connections",
		"Current SSL/TLS connections on the HAProxy process", nil)

	// #201: frontend capacity.
	c.frontendRequestsTotal = buildPrometheusDesc(c.subsystem, "frontend_requests_total",
		"Cumulative HTTP requests processed by this frontend", feLabels)
	c.frontendSessionLimit = buildPrometheusDesc(c.subsystem, "frontend_session_limit",
		"Configured session limit on this frontend", feLabels)

	// #201: backend latency (rolling averages over the last 1024 requests).
	c.backendQueueTimeAvg = buildPrometheusDesc(c.subsystem, "backend_queue_time_avg_seconds",
		"Average time spent in queue on this backend, over the last 1024 requests", beLabels)
	c.backendConnectTimeAvg = buildPrometheusDesc(c.subsystem, "backend_connect_time_avg_seconds",
		"Average time to connect to a server on this backend, over the last 1024 requests", beLabels)
	c.backendRespTimeAvg = buildPrometheusDesc(c.subsystem, "backend_response_time_avg_seconds",
		"Average server response time on this backend, over the last 1024 requests", beLabels)
	c.backendTotalTimeAvg = buildPrometheusDesc(c.subsystem, "backend_total_time_avg_seconds",
		"Average total request time on this backend, over the last 1024 requests", beLabels)
	c.backendSelectedTotal = buildPrometheusDesc(c.subsystem, "backend_selected_total",
		"Cumulative number of times this backend was selected by the load balancer (lbtot)", beLabels)
	c.backendAbortsTotal = buildPrometheusDesc(c.subsystem, "backend_aborts_total",
		"Cumulative aborted requests on this backend, by side", []string{"backend", "side"})

	// #201: server latency + health transitions.
	c.serverQueueTimeAvg = buildPrometheusDesc(c.subsystem, "server_queue_time_avg_seconds",
		"Average time spent in queue on this server, over the last 1024 requests", srvLabels)
	c.serverConnectTimeAvg = buildPrometheusDesc(c.subsystem, "server_connect_time_avg_seconds",
		"Average time to connect to this server, over the last 1024 requests", srvLabels)
	c.serverRespTimeAvg = buildPrometheusDesc(c.subsystem, "server_response_time_avg_seconds",
		"Average response time from this server, over the last 1024 requests", srvLabels)
	c.serverTotalTimeAvg = buildPrometheusDesc(c.subsystem, "server_total_time_avg_seconds",
		"Average total request time on this server, over the last 1024 requests", srvLabels)
	c.serverCheckDowns = buildPrometheusDesc(c.subsystem, "server_check_downs_total",
		"Cumulative number of UP->DOWN health-check transitions on this server", srvLabels)
	c.serverLastStateChange = buildPrometheusDesc(c.subsystem, "server_last_state_change_seconds",
		"Seconds since this server's last health-check state change", srvLabels)

	// #201: stick-table occupancy.
	tableLabels := []string{"table", "type"}
	c.stickTableSize = buildPrometheusDesc(c.subsystem, "stick_table_size",
		"Configured maximum entry count for this stick table", tableLabels)
	c.stickTableUsed = buildPrometheusDesc(c.subsystem, "stick_table_used",
		"Current entry count in this stick table", tableLabels)
}

func (c *haproxyCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.serviceRunning, c.procUptime, c.procCurrConns, c.procConnsTotal,
		c.procRequestsTotal, c.procIdlePercent,
		c.frontendStatus, c.frontendCurrSess, c.frontendSessTotal,
		c.frontendBytesIn, c.frontendBytesOut, c.frontendReqErrors,
		c.frontendReqDenied, c.frontendResponses,
		c.backendStatus, c.backendCurrSess, c.backendSessTotal,
		c.backendBytesIn, c.backendBytesOut, c.backendQueue,
		c.backendConnErrors, c.backendRespErrors, c.backendRetries,
		c.backendRedispatch, c.backendActiveSrv, c.backendBackupSrv,
		c.backendResponses,
		c.serverStatus, c.serverMaintenance, c.serverCurrSess, c.serverSessTotal,
		c.serverBytesIn, c.serverBytesOut, c.serverQueue,
		c.serverConnErrors, c.serverRespErrors, c.serverCheckFail,
		c.serverDowntime, c.serverWeight,
		c.connectionLimit, c.sslCurrentConnections,
		c.frontendRequestsTotal, c.frontendSessionLimit,
		c.backendQueueTimeAvg, c.backendConnectTimeAvg,
		c.backendRespTimeAvg, c.backendTotalTimeAvg,
		c.backendSelectedTotal, c.backendAbortsTotal,
		c.serverQueueTimeAvg, c.serverConnectTimeAvg,
		c.serverRespTimeAvg, c.serverTotalTimeAvg,
		c.serverCheckDowns, c.serverLastStateChange,
		c.stickTableSize, c.stickTableUsed,
	} {
		ch <- d
	}
}

func (c *haproxyCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchHAProxyStats()
	if err != nil {
		return err
	}

	// Plugin absent (counters 404): stay completely silent AND skip the
	// service-status probe — the service endpoint would just 404 too (D1).
	if !data.Present {
		return nil
	}

	// Plugin present but service stopped (null bodies → empty everything):
	// emit only service_running so the outage is visible.
	if len(data.Frontends) == 0 && len(data.Backends) == 0 &&
		len(data.Servers) == 0 && !data.HasInfo {
		status, present, sErr := client.FetchServiceStatusOptional("haproxyServiceStatus")
		if sErr != nil {
			c.log.Warn("failed to fetch haproxy service status", "err", sErr)
			return nil
		}
		if present {
			running := 0.0
			if status == "running" {
				running = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.serviceRunning, prometheus.GaugeValue,
				running, c.instance)
		}
		return nil
	}

	// emitOpt emits a metric only when v is non-nil — several #201 fields go
	// empty on rows/proxy-modes they don't apply to and must never be
	// fabricated as a 0 (#164).
	emitOpt := func(desc *prometheus.Desc, vt prometheus.ValueType, v *float64, labels ...string) {
		if v == nil {
			return
		}
		lbls := append(append([]string{}, labels...), c.instance)
		ch <- prometheus.MustNewConstMetric(desc, vt, *v, lbls...)
	}

	if data.HasInfo {
		ch <- prometheus.MustNewConstMetric(c.procUptime, prometheus.GaugeValue, data.Info.UptimeSeconds, c.instance)
		ch <- prometheus.MustNewConstMetric(c.procCurrConns, prometheus.GaugeValue, data.Info.CurrentConnections, c.instance)
		ch <- prometheus.MustNewConstMetric(c.procConnsTotal, prometheus.CounterValue, data.Info.ConnectionsTotal, c.instance)
		ch <- prometheus.MustNewConstMetric(c.procRequestsTotal, prometheus.CounterValue, data.Info.RequestsTotal, c.instance)
		ch <- prometheus.MustNewConstMetric(c.procIdlePercent, prometheus.GaugeValue, data.Info.IdlePercent, c.instance)
		emitOpt(c.connectionLimit, prometheus.GaugeValue, data.Info.ConnectionLimit)
		emitOpt(c.sslCurrentConnections, prometheus.GaugeValue, data.Info.SslCurrentConnections)
	}

	for _, fe := range data.Frontends {
		ch <- prometheus.MustNewConstMetric(c.frontendStatus, prometheus.GaugeValue, fe.StatusUp, fe.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.frontendCurrSess, prometheus.GaugeValue, fe.CurrentSessions, fe.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.frontendSessTotal, prometheus.CounterValue, fe.SessionsTotal, fe.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.frontendBytesIn, prometheus.CounterValue, fe.BytesIn, fe.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.frontendBytesOut, prometheus.CounterValue, fe.BytesOut, fe.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.frontendReqErrors, prometheus.CounterValue, fe.RequestErrors, fe.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.frontendReqDenied, prometheus.CounterValue, fe.RequestsDenied, fe.Name, c.instance)
		for code, v := range fe.ResponsesByCode {
			ch <- prometheus.MustNewConstMetric(c.frontendResponses, prometheus.CounterValue, v, fe.Name, code, c.instance)
		}
		emitOpt(c.frontendRequestsTotal, prometheus.CounterValue, fe.RequestsTotal, fe.Name)
		emitOpt(c.frontendSessionLimit, prometheus.GaugeValue, fe.SessionLimit, fe.Name)
	}

	for _, be := range data.Backends {
		ch <- prometheus.MustNewConstMetric(c.backendStatus, prometheus.GaugeValue, be.StatusUp, be.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.backendCurrSess, prometheus.GaugeValue, be.CurrentSessions, be.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.backendSessTotal, prometheus.CounterValue, be.SessionsTotal, be.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.backendBytesIn, prometheus.CounterValue, be.BytesIn, be.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.backendBytesOut, prometheus.CounterValue, be.BytesOut, be.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.backendQueue, prometheus.GaugeValue, be.QueueCurrent, be.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.backendConnErrors, prometheus.CounterValue, be.ConnectionErrors, be.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.backendRespErrors, prometheus.CounterValue, be.ResponseErrors, be.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.backendRetries, prometheus.CounterValue, be.Retries, be.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.backendRedispatch, prometheus.CounterValue, be.Redispatches, be.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.backendActiveSrv, prometheus.GaugeValue, be.ActiveServers, be.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.backendBackupSrv, prometheus.GaugeValue, be.BackupServers, be.Name, c.instance)
		for code, v := range be.ResponsesByCode {
			ch <- prometheus.MustNewConstMetric(c.backendResponses, prometheus.CounterValue, v, be.Name, code, c.instance)
		}
		emitOpt(c.backendQueueTimeAvg, prometheus.GaugeValue, be.QueueTimeAvg, be.Name)
		emitOpt(c.backendConnectTimeAvg, prometheus.GaugeValue, be.ConnectTimeAvg, be.Name)
		emitOpt(c.backendRespTimeAvg, prometheus.GaugeValue, be.ResponseTimeAvg, be.Name)
		emitOpt(c.backendTotalTimeAvg, prometheus.GaugeValue, be.TotalTimeAvg, be.Name)
		emitOpt(c.backendSelectedTotal, prometheus.CounterValue, be.SelectedTotal, be.Name)
		emitOpt(c.backendAbortsTotal, prometheus.CounterValue, be.ClientAborts, be.Name, "client")
		emitOpt(c.backendAbortsTotal, prometheus.CounterValue, be.ServerAborts, be.Name, "server")
	}

	for _, srv := range data.Servers {
		ch <- prometheus.MustNewConstMetric(c.serverStatus, prometheus.GaugeValue, srv.StatusUp, srv.Backend, srv.Name, c.instance)
		maintenance := 0.0
		if strings.HasPrefix(srv.Status, "MAINT") {
			maintenance = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.serverMaintenance, prometheus.GaugeValue,
			maintenance, srv.Backend, srv.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.serverCurrSess, prometheus.GaugeValue, srv.CurrentSessions, srv.Backend, srv.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.serverSessTotal, prometheus.CounterValue, srv.SessionsTotal, srv.Backend, srv.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.serverBytesIn, prometheus.CounterValue, srv.BytesIn, srv.Backend, srv.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.serverBytesOut, prometheus.CounterValue, srv.BytesOut, srv.Backend, srv.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.serverQueue, prometheus.GaugeValue, srv.QueueCurrent, srv.Backend, srv.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.serverConnErrors, prometheus.CounterValue, srv.ConnectionErrors, srv.Backend, srv.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.serverRespErrors, prometheus.CounterValue, srv.ResponseErrors, srv.Backend, srv.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.serverCheckFail, prometheus.CounterValue, srv.CheckFailures, srv.Backend, srv.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.serverDowntime, prometheus.CounterValue, srv.DowntimeSeconds, srv.Backend, srv.Name, c.instance)
		ch <- prometheus.MustNewConstMetric(c.serverWeight, prometheus.GaugeValue, srv.Weight, srv.Backend, srv.Name, c.instance)
		emitOpt(c.serverQueueTimeAvg, prometheus.GaugeValue, srv.QueueTimeAvg, srv.Backend, srv.Name)
		emitOpt(c.serverConnectTimeAvg, prometheus.GaugeValue, srv.ConnectTimeAvg, srv.Backend, srv.Name)
		emitOpt(c.serverRespTimeAvg, prometheus.GaugeValue, srv.ResponseTimeAvg, srv.Backend, srv.Name)
		emitOpt(c.serverTotalTimeAvg, prometheus.GaugeValue, srv.TotalTimeAvg, srv.Backend, srv.Name)
		emitOpt(c.serverCheckDowns, prometheus.CounterValue, srv.CheckDowns, srv.Backend, srv.Name)
		emitOpt(c.serverLastStateChange, prometheus.GaugeValue, srv.LastStateChangeSeconds, srv.Backend, srv.Name)
	}

	for _, tbl := range data.StickTables {
		ch <- prometheus.MustNewConstMetric(c.stickTableSize, prometheus.GaugeValue, tbl.Size, tbl.Table, tbl.Type, c.instance)
		ch <- prometheus.MustNewConstMetric(c.stickTableUsed, prometheus.GaugeValue, tbl.Used, tbl.Table, tbl.Type, c.instance)
	}

	status, present, sErr := client.FetchServiceStatusOptional("haproxyServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch haproxy service status", "err", sErr)
	} else if present {
		running := 0.0
		if status == "running" {
			running = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.serviceRunning, prometheus.GaugeValue,
			running, c.instance)
	}

	return nil
}
