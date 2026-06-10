<?php
namespace OPNsense\Sample\Api;

use OPNsense\Base\ApiControllerBase;

class ExampleController extends ApiControllerBase
{
    public function searchAction()
    {
        if ($this->request->isPost()) {
            return array("rows" => array());
        }
        return array();
    }

    public function statusAction()
    {
        return array("status" => "ok");
    }
}
