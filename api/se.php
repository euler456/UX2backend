<?php

class sqsSession
{
    //========================userfunction============================
    private $last_visit = 0;
    private $all_visit = Array();
    private $CustomerID = 0;
    private $username;
    private $email;
    private $phone;
    private $user_token;
    private $interval = 86400;
    private $limit = 1000;
    private $count = 0;
    /*public function getClientIp() {
        $ipaddress = '';
        if (isset($_SERVER['HTTP_CLIENT_IP']))
            $ipaddress = $_SERVER['HTTP_CLIENT_IP'];
        else if(isset($_SERVER['HTTP_X_FORWARDED_FOR']))
            $ipaddress = $_SERVER['HTTP_X_FORWARDED_FOR'];
        else if(isset($_SERVER['HTTP_X_FORWARDED']))
            $ipaddress = $_SERVER['HTTP_X_FORWARDED'];
        else if(isset($_SERVER['HTTP_FORWARDED_FOR']))
            $ipaddress = $_SERVER['HTTP_FORWARDED_FOR'];
        else if(isset($_SERVER['HTTP_FORWARDED']))
            $ipaddress = $_SERVER['HTTP_FORWARDED'];
        else if(isset($_SERVER['REMOTE_ADDR']))
            $ipaddress = $_SERVER['REMOTE_ADDR'];
        else
            $ipaddress = 'UNKNOWN';
        return $ipaddress;
    }*/
    
    public function input_testing($data)
    {
        $data = trim($data);
        $data = stripslashes($data);
        $data = htmlspecialchars($data);
        return $data;
    }
    public function __construct()
    {
        $this->origin = 'https://ux2website.herokuapp.com';
    }
    public function is_rate_limited()
    {
        if ($this->last_visit == 0) {
            $this->last_visit = time();
            return false;
        }
        if ($this->last_visit <= time()-1) {
            return true;
        }
        return false;
    }
    public function day_rate_limited()
    {
        $this->oneday =time()- $this->interval;
        $this->all_visit[]=$this->last_visit;
        foreach($this->all_visit as $times){
            if($times < $this->oneday){
                $key = array_search($times,$this->all_visit);
                array_splice($this->all_visit,$key);
            }
        }
        if(count($this->all_visit)> $this->limit){
            return true;
        }
        else{
            return false;
        }
        /*  $now = time();
        if ($now < $this->last_visit + $this->interval) {
            if ($this->count < $this->limit) {
                $this->count++;
                return true;
            } else {
                return false;
            } }

            else {
                $this->last_visit = $now;
                $this->count = 1;}*/
    }

    public function login($username, $password)
    {
        global $sqsdb;

        $res = $sqsdb->checkLogin($username, $password);
        if ($res === false) {
            return false;
        } elseif (count($res) > 1) {
            $this->CustomerID = $res['CustomerID'];
            $this->user_token = md5(json_encode($res));
            return array(
                'username' => $res['username'],
                'email' => $res['email'],
                'phone' => $res['phone'],
                'Hash' => $this->user_token
            );
        } elseif (count($res) == 1) {
            $this->CustomerID = $res['CustomerID'];
            $this->user_token = md5(json_encode($res));
            return array('Hash' => $this->user_token);
        }
    }
    public function register($username, $email, $phone, $postcode, $password, $csrf)
    {
        global $sqsdb;
        if ($sqsdb->registerUser( $username,  $email, $phone, $postcode, $password)) {
            return true;
        } else {
            return 0;
        }
    }
    public function update($username, $email, $phone, $postcode, $password)
    {
        global $sqsdb;
        if ($sqsdb->updateprofile($this->CustomerID, $username,  $email, $phone, $postcode, $password)) {
            return true;
        } else {
            return 0;
        }
    }
    public function logEvent($ip_addr,$action,$PHPSESSID)
    {

        global $sqsdb;
        if ($sqsdb->logevent($this->CustomerID, $ip_addr,$action,$PHPSESSID)) {
            return true;
        } else {
            return 0;
        }
    }
    public function isLoggedIn()
    {
        if ($this->CustomerID === 0) {
            return false;
        } else {
            return array('Hash' => $this->user_token);
        }
    }
    public function logout()
    {
        $this->CustomerID = 0;
    }
    public function validate($type, $dirty_string)
    {
    }
   

    //===========================productfunction================================================
    public function display()
    {
        global $sqsdb;
        $result=$sqsdb->displayfood();
        return $result;
    }
   
    public function createorder()
    {
        global $sqsdb;
        if ($sqsdb->createorderform($this->CustomerID)) {
            return true;
        } else {
            return 0;
        }
    }
    //==================admin food control============
    public function addfood($foodname,$price, $description,$options,$image) {
        global $sqsdb;
            if($sqsdb->addfooditem($foodname,$price,$description,$options,$image)) {
                return true;
            } else {
                return false;
            }
        }
    public function deleteFOOD($F_ID) {
            global $sqsdb;
                if($sqsdb->deletefood($F_ID)) {
                    return true;
                } else {
                    return false;
                }
            }
    public function updatefood($F_ID,$foodname,$price, $description,$options,$image) {
            global $sqsdb;
                    if($sqsdb->updatefooditem($F_ID,$foodname,$price,$description,$options,$image)) {
                        return true;
                    } else {
                        return false;
                    }
                }
    //====================orderfunction===============================
    public function displayorder()
    {
        global $sqsdb;
        $result=$sqsdb->displayorderfood();
        return $result;
    }
    public function orderquantity($F_ID, $foodname, $price, $quantity, $totalprice)
    {
        global $sqsdb;
        if ($sqsdb->orderquantityfood($F_ID, $foodname, $price, $quantity, $totalprice, $this->CustomerID)) {
            return true;
        } else {
            return false;
        }
    }
    public function showorderform()
    {
        global $sqsdb;
      //  $sqsdb->displayshoworderform($this->CustomerID);
        $result=$sqsdb->displayshoworderform($this->CustomerID);
        return $result;
    }
    public function orderdelete($orderitem_ID)
    {
        global $sqsdb;
        if ($sqsdb->deleteorderfood($orderitem_ID)) {
            return true;
        } else {
            return false;
        }
    }
    public function orderID()
    {
        global $sqsdb;
        $sqsdb->getorderID($this->CustomerID);
        return $sqsdb;
    }
    //====================paymentfunction===============================
    public function confirmorderform()
    {
        global $sqsdb;
     
        $result=$sqsdb->getconfirmorderform($this->CustomerID);
        return $result;
    }
    public function sumtotalprice()
    {
        global $sqsdb;
        if ($sqsdb->sumtotalpriceff($this->CustomerID)) {
            return true;
        } else {
            return false;
        };
        return $sqsdb;
    }
    public function checkout($cname, $ccnum, $expmonth, $expyear, $cvv)
    {
        global $sqsdb;
        if ($sqsdb->checkoutff($this->CustomerID, $cname, $ccnum, $expmonth, $expyear, $cvv)) {
            return true;
        } else {
            return false;
        }
    }
    public function checkoutupdate()
    {
        global $sqsdb;
        if ($sqsdb->checkoutupdateff($this->CustomerID)) {
            return true;
        } else {
            return false;
        }
        return $sqsdb;
    }
   
//=============admin


public function adminlogin($username, $password)
{
    global $sqsdb;

    $res = $sqsdb->admincheckLogin($username, $password);
    if ($res === false) {
        return false;
    } elseif (count($res) > 1) {
        $this->CustomerID = $res['CustomerID'];
        $this->user_token = md5(json_encode($res));
        return array(
            'username' => $res['username'],
            'email' => $res['email'],
            'phone' => $res['phone'],
            'usertype' => $res['usertype'],
            'Hash' => $this->user_token
        );
    } elseif (count($res) == 1) {
        $this->CustomerID = $res['CustomerID'];
        $this->user_token = md5(json_encode($res));
        return array('Hash' => $this->user_token);
    }
}
public function registeradmin($username, $email, $phone, $postcode, $password)
{
    global $sqsdb;
    if ($sqsdb->registerUseradmin( $username,  $email, $phone, $postcode, $password)) {
        return true;
    } else {
        return 0;
    }
}
public function adminupdate($username, $email, $phone, $postcode, $password)
{
    global $sqsdb;
    if ($sqsdb->updateprofile($this->CustomerID, $username,  $email, $phone, $postcode, $password)) {
        return true;
    } else {
        return 0;
    }
}

public function adminlogEvent($ip_addr,$action,$PHPSESSID)
{
    global $sqsdb;
    if ($sqsdb->adminlogevent($this->CustomerID,$ip_addr,$action,$PHPSESSID)) {
        return true;
    } else {
        return 0;
    }
}
function displayuser()
{
global $sqsdb;
$result=$sqsdb->userdisplay();
return $result;
}
function adduser($username, $email, $phone, $postcode, $password,$usertype)
{
global $sqsdb;
if ($sqsdb->useradd($username, $email, $phone, $postcode, $password,$usertype)) {
    return true;
} else {
    return false;
}
}
function deleteuser($CustomerID)
{
global $sqsdb;
if ($sqsdb->userdelete($CustomerID)) {
    return true;
} else {
    return false;
}
}
function updateuser($CustomerID, $username, $email, $phone, $postcode, $password,$usertype)
{
global $sqsdb;
if ($sqsdb->userupdate($CustomerID, $username, $email, $phone, $postcode, $password,$usertype)) {
    return true;
} else {
    return false;
}
}
}
