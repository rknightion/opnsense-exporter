# Kea reservation search fixtures

These are source-derived decoder fixtures, not live captures. They retain only the fields consumed by the aggregate inventory decoder: the raw `subnet` ModelRelationField UUID and UIModelGrid's `%subnet` description. They intentionally omit reservation identity and all reservation attributes.

Source: OPNsense core tag `26.1.11` commit `c930ab586ffe2d2e010e5135657e5e054316ff58` and tag `26.7.3` commit `368b814d349ad832c13bf5dbe3444acb1040d83e`:

- `src/opnsense/mvc/app/controllers/OPNsense/Kea/Api/Dhcpv4Controller.php`, `searchReservationAction()` calls `searchBase("reservations.reservation", null, "hw_address")`.
- `src/opnsense/mvc/app/controllers/OPNsense/Kea/Api/Dhcpv6Controller.php`, `searchReservationAction()` calls `searchBase("reservations.reservation", null, "duid")`.
- `src/opnsense/mvc/app/models/OPNsense/Kea/KeaDhcpv4.xml` defines the reservation `subnet` relation to `subnets.subnet4`, displayed as `subnet`; `KeaDhcpv6.xml` defines it to `subnets.subnet6`, displayed as `interface,subnet` with `%s %s` formatting.
- `src/opnsense/mvc/app/library/OPNsense/Base/UIModelGrid.php` emits raw field values and `%field` descriptions when they differ, and defaults an absent `rowCount` to `-1` (all rows).

The populated response has no `rowCount` request parameter and contains two configured rows, proving the inventory is read as the whole UIModelGrid recordset rather than a page. It is synthetic solely to pin those released source branches.
