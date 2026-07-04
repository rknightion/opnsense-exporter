<?php
namespace OPNsense\Abstract\Api;

use OPNsense\Base\ApiControllerBase;

// An abstract (non-instantiable) base controller, like OPNsense's filter_base or the Kea
// Leases base. It is never registered as a routable MVC controller, so extract.py must
// emit NO endpoints for it — paths built from it 404 live (#146).
abstract class BaseController extends ApiControllerBase
{
    public function searchAction()
    {
        return array("rows" => array());
    }
}
