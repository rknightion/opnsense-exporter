package options

import "testing"

func TestUDPReceiveBufferDefaults(t *testing.T) {
	if got := LogsSyslogUDPReceiveBufferBytes(); got != DefaultUDPReceiveBufferBytes {
		t.Fatalf("syslog UDP receive buffer default = %d, want %d", got, DefaultUDPReceiveBufferBytes)
	}
	if got := FlowNetflowUDPReceiveBufferBytes(); got != DefaultUDPReceiveBufferBytes {
		t.Fatalf("NetFlow UDP receive buffer default = %d, want %d", got, DefaultUDPReceiveBufferBytes)
	}
}

func TestUDPReceiveBufferValidationRejectsNegativeValues(t *testing.T) {
	if err := (FlowConfig{NetflowUDPReceiveBuffer: -1}).Validate(); err == nil {
		t.Fatal("negative NetFlow UDP receive buffer was accepted")
	}

	oldEnabled := *logsSyslogEnabled
	oldUDPAddr := *logsSyslogListenUDP
	oldBuffer := *logsSyslogUDPReceiveBuffer
	t.Cleanup(func() {
		*logsSyslogEnabled = oldEnabled
		*logsSyslogListenUDP = oldUDPAddr
		*logsSyslogUDPReceiveBuffer = oldBuffer
	})
	*logsSyslogEnabled = true
	*logsSyslogListenUDP = ":5514"
	*logsSyslogUDPReceiveBuffer = -1
	if _, _, err := LogsSyslog(); err == nil {
		t.Fatal("negative syslog UDP receive buffer was accepted")
	}
}
