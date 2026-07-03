<?php
namespace OPNsense\Bad\Api;

use OPNsense\Base\ApiControllerBase;

// Reproduces the class of failure from #111: a third-party plugin controller using PHP
// syntax the aging vendored phply grammar cannot parse. The original report was a
// Zenarmor class-constant array dereference (ConfigModel::Databases[$i]); newer phply
// versions tolerate that, so this fixture uses a PHP 8.1 `enum` — still outside the
// grammar's support — to keep exercising the skip-and-warn path. The test asserts the
// tool skips this file and continues, regardless of which exact construct trips it.
enum Database: string
{
    case Primary = 'primary';
    case Replica = 'replica';
}

class InstallerController extends ApiControllerBase
{
    public function installAction()
    {
        return array("status" => Database::Primary->value);
    }
}
