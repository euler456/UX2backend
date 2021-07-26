<?php

include_once("./core.php");
require_once('../vendor/autoload.php');
require_once('./se.php');
require_once('./userfunction.php');

//sqsuser is from the userfunction.php which represent database
$sqsdb = new sqsuser;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Attribute\AttributeBag;
use Symfony\Component\HttpFoundation\Session\Storage\NativeSessionStorage;
use Symfony\Component\HttpFoundation\RedirectResponse;

$request = Request::createFromGlobals();
$response = new Response();
$session = new Session(new NativeSessionStorage(), new AttributeBag());
$http_origin = $_SERVER['HTTP_ORIGIN'];
if ( $http_origin == 'https://proj3frontend.herokuapp.com' || $http_origin == 'https://ux2website.herokuapp.com'  )
{
    $response->headers->set('Access-Control-Allow-Origin', $http_origin);
}
else{
    $response->setStatusCode(400);
}
$response->headers->set('Content-Type', 'application/json');
$response->headers->set('Access-Control-Allow-Headers', 'origin, content-type, accept');
$response->headers->set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
//$response->headers->set('Access-Control-Allow-Origin', 'https://ux2website.herokuapp.com');
$response->headers->set('Access-Control-Allow-Credentials', 'true');
//put session here because here is the place the action started
ini_set('session.cookie_samesite',"None");
ini_set('session.cookie_secure', "1");
$session->start();

if (!$session->has('sessionObj')) {
    $session->set('sessionObj', new sqsSession);
}
if (empty($request->query->all())) {
    $response->setStatusCode(400);
} 
elseif ($request->cookies->has('PHPSESSID')) {
  
    if ($session->get('sessionObj')->is_rate_limited()) {
        $response->setStatusCode(429);
    }
    if ($session->get('sessionObj')->day_rate_limited()) {
        $response->setStatusCode(429);

    }
    //if the request is post , the code will start the action which is in the POST Block
    if ($request->getMethod() == 'POST') {  
           // register
        if ($request->query->getAlpha('action') == 'register') {
            if ($request->request->has('username')) {
                $res = $sqsdb->userExists($request->request->get('username'));
                if ($res) {
                    $response->setStatusCode(418);
                } else {
                    if (
                        $request->request->has('username') and
                        $request->request->has('email') and
                        $request->request->has('phone') and
                        $request->request->has('postcode') and
                        $request->request->has('password') and
                        $request->request->has('password2')
                    ) {
                        $username=$session->get('sessionObj')->input_testing($request->request->getAlpha('username'));
                        $email=$session->get('sessionObj')->input_testing($request->request->get('email'));
                        $phone=$session->get('sessionObj')->input_testing($request->request->get('phone'));
                        $postcode=$session->get('sessionObj')->input_testing($request->request->get('postcode'));
                        $password=$session->get('sessionObj')->input_testing($request->request->get('password'));
                        $res = $session->get('sessionObj')->register(
                            $username,
                            $email,
                            $phone,
                            $postcode,
                            $password,
                            $request->request->get('csrf')
                        );
                        if ($res === true) {
                            $response->setStatusCode(201);
                        } elseif ($res === false) {
                            $response->setStatusCode(403);
                        } elseif ($res === 0) {
                            $response->setStatusCode(500);
                        }
                    }
                }
            } else {
                $response->setStatusCode(400);
            }
        } elseif ($request->query->getAlpha('action') == 'login') {
            if ($request->request->has('username') and $request->request->has('password')) {
                $username=$session->get('sessionObj')->input_testing($request->request->getAlpha('username'));
                $password=$session->get('sessionObj')->input_testing($request->request->get('password'));
                $res = $session->get('sessionObj')->login(
                    $username,
                    $password
                );
                if ($res === false) {
                    $response->setContent(json_encode($request->request));
                    $response->setStatusCode(401);
                } elseif (count($res) == 1) {
                    $response->setStatusCode(203);
                    $response->setContent(json_encode($res));
                } elseif (count($res) > 1) {
                    $response->setStatusCode(200);
                    $response->setContent(json_encode($res));
                    $res =$session->get('sessionObj')->logEvent($request->getClientIp(),'login',$request->cookies->get('PHPSESSID'));
                }
            } else {
                $response->setContent(json_encode($request));
                $response->setStatusCode(404);
            }
        } elseif ($request->query->getAlpha('action') == 'isloggedin') {
            $res = $session->get('sessionObj')->isLoggedIn();
            if ($res == false) {
                $response->setStatusCode(403);
            } elseif (count($res) == 1) {
                $response->setStatusCode(203);
                $response->setContent(json_encode($res));
            }
        } elseif ($request->query->getAlpha('action') == 'update') {
            $res =$session->get('sessionObj')->logEvent($request->getClientIp(),'update',$request->cookies->get('PHPSESSID'));
            $res = $session->get('sessionObj')->isLoggedIn();
            if (($request->request->has('username')) && (count($res) == 1)) {
                $res = $sqsdb->userExists($request->request->get('username'));

                if ($res) {
                    $response->setStatusCode(400);
                } else {
                    if (
                        $request->request->has('currentusername') and
                        $request->request->has('username') and
                        $request->request->has('email') and
                        $request->request->has('phone') and
                        $request->request->has('postcode') and
                        $request->request->has('password') and
                        $request->request->has('password2')
                    ) {
                        $username=$session->get('sessionObj')->input_testing($request->request->getAlpha('username'));
                        $email=$session->get('sessionObj')->input_testing($request->request->get('email'));
                        $phone=$session->get('sessionObj')->input_testing($request->request->get('phone'));
                        $postcode=$session->get('sessionObj')->input_testing($request->request->get('postcode'));
                        $password=$session->get('sessionObj')->input_testing($request->request->get('password'));
                        $res = $session->get('sessionObj')->update(
                            //    $res = $sqsdb->userid($request->request->get('currentusername')),
                            $username,
                            $email,
                            $phone,
                            $postcode,
                            $password,
                            $csrf
                        );
                        if ($res === true) {
                            $response->setStatusCode(201);
                        } elseif ($res === false) {
                            $response->setStatusCode(403);
                        } elseif ($res === 0) {
                            $response->setStatusCode(500);
                        }
                    }
                }
            } else {
                $response->setStatusCode(402);
            }
        } elseif ($request->query->getAlpha('action') == 'displayorderfood') {
            $res = $session->get('sessionObj')->displayorder();
            $response->setContent(json_encode($res));
            $response->setStatusCode(200);
        } elseif ($request->query->getAlpha('action') == 'orderdelete') {
            $res =$session->get('sessionObj')->logEvent($request->getClientIp(),'orderdelete',$request->cookies->get('PHPSESSID'));
            $res = $session->get('sessionObj')->orderdelete(
                $request->request->get('orderitem_ID')
            );
            if ($res === true) {
                $response->setStatusCode(201);
            } elseif ($res === false) {
                $response->setStatusCode(403);
            } elseif ($res === 0) {
                $response->setStatusCode(500);
            }
        } elseif ($request->query->getAlpha('action') == 'orderquantity') {
            $res =$session->get('sessionObj')->logEvent($request->getClientIp(),'orderfood',$request->cookies->get('PHPSESSID'));
            if (
                $request->request->has('F_ID') and
                $request->request->has('foodname') and
                $request->request->has('price') and
                $request->request->has('quantity') and
                $request->request->has('totalprice')
            ) {
                $res = $session->get('sessionObj')->orderquantity(
                    $request->request->get('F_ID'),
                    $request->request->get('foodname'),
                    $request->request->get('price'),
                    $request->request->get('quantity'),
                    $request->request->get('totalprice')
                );
                if ($res === true) {
                    $response->setStatusCode(201);
                } elseif ($res === false) {
                    $response->setStatusCode(403);
                } elseif ($res === 0) {
                    $response->setStatusCode(500);
                }
            } else {
                $response->setStatusCode(400);
            }
        } elseif ($request->query->getAlpha('action') == 'displayfood') {
            $res = $session->get('sessionObj')->isLoggedIn();
            if ($res == false) {
                $response->setStatusCode(403);
            } elseif (count($res) == 1) {
                $res = $session->get('sessionObj')->displayorder();
                $response->setContent(json_encode($res));
                $response->setStatusCode(200);
            }
        } elseif ($request->query->getAlpha('action') == 'addfood') {
            if (
                $request->request->has('foodname') and
                $request->request->has('price')   and
                $request->request->has('description') and
                $request->request->has('image') and
                $request->request->has('options')
            ) {
                $response->setStatusCode(201);
                $res =$session->get('sessionObj')->adminlogEvent($request->getClientIp(),'addfood',$request->cookies->get('PHPSESSID'));
                $foodname=$session->get('sessionObj')->input_testing($request->request->get('foodname'));
                $price=$session->get('sessionObj')->input_testing($request->request->get('price'));
                $description=$session->get('sessionObj')->input_testing($request->request->get('description'));
                $options=$session->get('sessionObj')->input_testing($request->request->get('options'));                $password=$session->get('sessionObj')->input_testing($request->request->get('password'));
                $image=$session->get('sessionObj')->input_testing($request->request->get('image'));

                $res = $session->get('sessionObj')->addfood(
                    $foodname,
                    $price,
                    $description,
                    $options,
                    $image
                );
                if ($res === true) {
                    $response->setStatusCode(201);
                } elseif ($res === false) {
                    $response->setStatusCode(403);
                } elseif ($res === 0) {
                    $response->setStatusCode(500);
                }
            } else {
                $response->setStatusCode(400);
            }
        } elseif ($request->query->getAlpha('action') == 'deleteFOOD') {
            $res = $session->get('sessionObj')->deleteFOOD(
                $request->request->get('F_ID')
            );
            if ($res === true) {
                $res =$session->get('sessionObj')->adminlogEvent($request->getClientIp(),'delete food',$request->cookies->get('PHPSESSID'));
                $response->setStatusCode(201);
            } elseif ($res === false) {
                $response->setStatusCode(403);
            } elseif ($res === 0) {
                $response->setStatusCode(500);
            }
        } elseif ($request->query->getAlpha('action') == 'updatefood') {
            if (
                $request->request->has('F_ID') and
                $request->request->has('foodname') and
                $request->request->has('price')   and
                $request->request->has('description') and
                $request->request->has('image') and
                $request->request->has('options')
            ) {
                $F_ID=$session->get('sessionObj')->input_testing($request->request->get('F_ID'));
                $foodname=$session->get('sessionObj')->input_testing($request->request->get('foodname'));
                $price=$session->get('sessionObj')->input_testing($request->request->get('price'));
                $description=$session->get('sessionObj')->input_testing($request->request->get('description'));
                $options=$session->get('sessionObj')->input_testing($request->request->get('options'));                $password=$session->get('sessionObj')->input_testing($request->request->get('password'));
                $image=$session->get('sessionObj')->input_testing($request->request->get('image'));
                $res = $session->get('sessionObj')->updatefood(
                    $F_ID,
                    $foodname,
                    $price,
                    $description,
                    $options,
                    $image
                );
                if ($res === true) {
                    $res =$session->get('sessionObj')->adminlogEvent($request->getClientIp(),'update food',$request->cookies->get('PHPSESSID'));
                    $response->setStatusCode(201);
                } elseif ($res === false) {
                    $response->setStatusCode(403);
                } elseif ($res === 0) {
                    $response->setStatusCode(500);
                }
            } else {
                $response->setStatusCode(400);
            }
        } elseif ($request->query->getAlpha('action') == 'createorder') {
            $res = $session->get('sessionObj')->isLoggedIn();
            if ($res == false) {
                $response->setStatusCode(403);
            } else {
                $res = $session->get('sessionObj')->createorder();
                if ($res === true) {
                    $response->setStatusCode(201);
                    $res =$session->get('sessionObj')->logEvent($request->getClientIp(),'start order',$request->cookies->get('PHPSESSID'));
                } elseif ($res === false) {
                    $response->setStatusCode(403);
                } elseif ($res === 0) {
                    $response->setStatusCode(500);
                } else {
                    $response->setStatusCode(400);
                }
            }
        } elseif ($request->query->getAlpha('action') == 'checkout') {
            $res =$session->get('sessionObj')->logEvent($request->getClientIp(),'checkout',$request->cookies->get('PHPSESSID'));
            $cname=$session->get('sessionObj')->input_testing($request->request->get('cname'));
            $ccnum=$session->get('sessionObj')->input_testing($request->request->get('ccnum'));
            $expmonth=$session->get('sessionObj')->input_testing($request->request->get('expmonth'));
            $cvv=$session->get('sessionObj')->input_testing($request->request->get('cvv'));
            $res = $session->get('sessionObj')->checkout(
                $cname,
                $ccnum,
                $expmonth,
                $expyear,
                $cvv
            );
            if ($res === true) {
                $response->setStatusCode(201);
            } elseif ($res === false) {
                $response->setStatusCode(403);
            } elseif ($res === 0) {
                $response->setStatusCode(500);
            }
        } elseif ($request->query->getAlpha('action') == 'checkoutupdate') {
            $res = $session->get('sessionObj')->checkoutupdate($request->request->get('orderID'));
            if ($res === true) {
                $response->setStatusCode(201);
            } elseif ($res === false) {
                $response->setStatusCode(403);
            } elseif ($res === 0) {
                $response->setStatusCode(500);
            }

        }  //==========admin==================
        elseif ($request->query->getAlpha('action') == 'registeradmin') {
           if ($request->request->has('username')) {
               $res = $sqsdb->userExists($request->request->get('username'));
               if ($res) {
                   $response->setStatusCode(418);
               } else {
                   if (
                       $request->request->has('username') and
                       $request->request->has('email') and
                       $request->request->has('phone') and
                       $request->request->has('postcode') and
                       $request->request->has('password') and
                       $request->request->has('password2')
                   ) {
                    $username=$session->get('sessionObj')->input_testing($request->request->getAlpha('username'));
                    $email=$session->get('sessionObj')->input_testing($request->request->get('email'));
                    $phone=$session->get('sessionObj')->input_testing($request->request->get('phone'));
                    $postcode=$session->get('sessionObj')->input_testing($request->request->get('postcode'));
                    $password=$session->get('sessionObj')->input_testing($request->request->get('password'));
                       $res = $session->get('sessionObj')->registeradmin(
                           $username,
                           $email,
                           $phone,
                           $postcode,
                           $password,
                           $csrf
                       );
                       if ($res === true) {
                           $response->setStatusCode(201);
                       } elseif ($res === false) {
                           $response->setStatusCode(403);
                       } elseif ($res === 0) {
                           $response->setStatusCode(500);
                       }
                   }
               }
           } else {
               $response->setStatusCode(400);
           }
       } elseif ($request->query->getAlpha('action') == 'adminlogin') {
           if ($request->request->has('username') and $request->request->has('password')) {
               $res = $session->get('sessionObj')->adminlogin(
                   $request->request->get('username'),
                   $request->request->get('password')
               );
               if ($res === false) {
                   $response->setContent(json_encode($request->request));
                   $response->setStatusCode(401);
               } elseif (count($res) == 1) {
                   $response->setStatusCode(203);
                   $response->setContent(json_encode($res));
               } elseif (count($res) > 1) {
                   $res =$session->get('sessionObj')->adminlogEvent($request->getClientIp(),'admin login',$request->cookies->get('PHPSESSID'));
                   $response->setStatusCode(200);
                   $response->setContent(json_encode($res));
               }
           } else {
               $response->setContent(json_encode($request));
               $response->setStatusCode(404);
           }
       } elseif ($request->query->getAlpha('action') == 'adminupdate') {
           $res = $session->get('sessionObj')->isLoggedIn();
           if (($request->request->has('username')) && ($res != false)) {
               $res = $sqsdb->userExists($request->request->get('username'));
               if ($res) {
                   $response->setStatusCode(400);
               } else {
                   if (
                       $request->request->has('currentusername') and
                       $request->request->has('username') and
                       $request->request->has('email') and
                       $request->request->has('phone') and
                       $request->request->has('postcode') and
                       $request->request->has('password') and
                       $request->request->has('password2')
                   ) {
                    $username=$session->get('sessionObj')->input_testing($request->request->getAlpha('username'));
                    $email=$session->get('sessionObj')->input_testing($request->request->get('email'));
                    $phone=$session->get('sessionObj')->input_testing($request->request->get('phone'));
                    $postcode=$session->get('sessionObj')->input_testing($request->request->get('postcode'));
                    $password=$session->get('sessionObj')->input_testing($request->request->get('password'));
                       $res = $session->get('sessionObj')->adminupdate(
                           //    $res = $sqsdb->userid($request->request->get('currentusername')),
                           $username,
                           $email,
                           $phone,
                           $postcode,
                           $password,
                           $csrf
                       );
                       if ($res === true) {
                           $res =$session->get('sessionObj')->adminlogEvent($request->getClientIp(),'edit profile',$request->cookies->get('PHPSESSID'));
                           $response->setStatusCode(201);
                       } elseif ($res === false) {
                           $response->setStatusCode(403);
                       } elseif ($res === 0) {
                           $response->setStatusCode(500);
                       }
                   }
               }
            }
            
            }
            elseif ($request->query->getAlpha('action') == 'displayuser') {
                $res = $session->get('sessionObj')->isLoggedIn();
                if ($res == false) {
                    $response->setStatusCode(400);}
                    else{
                    $res = $session->get('sessionObj')->displayuser();
                    $response->setContent(json_encode($res));
            $response->setStatusCode(200);
                } 
            } elseif ($request->query->getAlpha('action') == 'adduser') {
                $res = $session->get('sessionObj')->isLoggedIn();
                if ($res == false) {
                    $response->setStatusCode(400);}
                    else{
                    if (
                        $request->request->has('username') and
                        $request->request->has('email') and
                        $request->request->has('phone') and
                        $request->request->has('postcode') and
                        $request->request->has('password') and
                        $request->request->has('usertype')
                    ){
                        $response->setStatusCode(201);
                        $username=$session->get('sessionObj')->input_testing($request->request->getAlpha('username'));
                        $email=$session->get('sessionObj')->input_testing($request->request->get('email'));
                        $phone=$session->get('sessionObj')->input_testing($request->request->get('phone'));
                        $postcode=$session->get('sessionObj')->input_testing($request->request->get('postcode'));    
                        $password=$session->get('sessionObj')->input_testing($request->request->get('password'));
                        $usertype=$session->get('sessionObj')->input_testing($request->request->get('usertype'));
                        $res = $session->get('sessionObj')->adduser(
                            $username,
                            $email,
                            $phone,
                            $postcode,
                            $password,
                            $usertype
                        );
                        if ($res === true) {
                            $res =$session->get('sessionObj')->adminlogEvent($request->getClientIp(),'adduser',$request->cookies->get('PHPSESSID'));
                            $response->setStatusCode(201);
                        } elseif ($res === false) {
                            $response->setStatusCode(403);
                        } elseif ($res === 0) {
                            $response->setStatusCode(500);
                        }
                    } else {
                        $response->setStatusCode(400);
                    }
                } 
            } elseif ($request->query->getAlpha('action') == 'deleteuser') {
                $res = $session->get('sessionObj')->isLoggedIn();
                if ($res === false) {
                    $response->setStatusCode(400);}
                    else{
                    $res = $session->get('sessionObj')->deleteuser(
                        $request->request->get('CustomerID')
                    );
                    if ($res === true) {
                        $res =$session->get('sessionObj')->adminlogEvent($request->getClientIp(),'delete user',$request->cookies->get('PHPSESSID'));
                        $response->setStatusCode(201);
                    } elseif ($res === false) {
                        $response->setStatusCode(403);
                    } elseif ($res === 0) {
                        $response->setStatusCode(500);
                    }
                } 
            } elseif ($request->query->getAlpha('action') == 'updateuser') {
                $res = $session->get('sessionObj')->isLoggedIn();
                if ($res === false) {
                    $response->setStatusCode(400);}
                    else{
                    if (
                        $request->request->has('CustomerID') and
                        $request->request->has('username') and
                        $request->request->has('email') and
                        $request->request->has('phone') and
                        $request->request->has('postcode') and
                        $request->request->has('password') and 
                        $request->request->has('usertype')
                    ) {
                        $username=$session->get('sessionObj')->input_testing($request->request->getAlpha('username'));
                        $email=$session->get('sessionObj')->input_testing($request->request->get('email'));
                        $phone=$session->get('sessionObj')->input_testing($request->request->get('phone'));
                        $postcode=$session->get('sessionObj')->input_testing($request->request->get('postcode'));    
                        $password=$session->get('sessionObj')->input_testing($request->request->get('password'));
                        $usertype=$session->get('sessionObj')->input_testing($request->request->get('usertype'));
                        $res = $session->get('sessionObj')->updateuser(
                            $request->request->get('CustomerID'),
                            $username,                                
                            $email,
                                $phone,
                                $postcode,
                                $password,
                                $usertype
                        );
                        if ($res === true) {
                            $response->setStatusCode(201);
                            $res =$session->get('sessionObj')->adminlogEvent($request->getClientIp(),'update user',$request->cookies->get('PHPSESSID'));
                        } elseif ($res === false) {
                            $response->setStatusCode(403);
                        } elseif ($res === 0) {
                            $response->setStatusCode(500);
                        }
                    } else {
                        $response->setStatusCode(400);
                    }
                } 
            }
        else {
            $response->setStatusCode(400);
        }
    }
    //if the request from the front-end JS is GET , the code will start the action which is in the GET Block
    if ($request->getMethod() == 'GET') {     
        if ($request->query->getAlpha('action') == 'accountexists') {
            if ($request->query->has('username')) {
                $res = $sqsdb->userExists($request->query->get('username'));
                if ($res) {
                    $response->setStatusCode(400);
                } else {
                    $response->setStatusCode(204);
                }
            }
        } elseif ($request->query->getAlpha('action') == 'logout') {
           
            $res =$session->get('sessionObj')->logEvent($request->getClientIp(),'logout',$request->cookies->get('PHPSESSID'));
            $session->get('sessionObj')->logout();
            $response->setStatusCode(200);
           
        } 
        elseif ($request->query->getAlpha('action') == 'adminlogout') {
           
            $res =$session->get('sessionObj')->adminlogEvent($request->getClientIp(),'logout',$request->cookies->get('PHPSESSID'));
            $session->get('sessionObj')->logout();
            $response->setStatusCode(200);
           
        }
        elseif ($request->query->getAlpha('action') == 'orderID') {
            $res = $session->get('sessionObj')->orderID();
        } elseif ($request->query->getAlpha('action') == 'sumtotalprice') {
            $res =$session->get('sessionObj')->logEvent($request->getClientIp(),'complete order',$request->cookies->get('PHPSESSID'));
            $res = $session->get('sessionObj')->sumtotalprice();
            if ($res === true) {
                $response->setStatusCode(201);
            } elseif ($res === false) {
                $response->setStatusCode(403);
            } elseif ($res === 0) {
                $response->setStatusCode(500);
            } else {
                $response->setStatusCode(418);
            }
        } elseif ($request->query->getAlpha('action') == 'showorderform') {
            $res = $session->get('sessionObj')->showorderform();
            $response->setContent(json_encode($res));
            $response->setStatusCode(200);
        } elseif ($request->query->getAlpha('action') == 'confirmorderform') {
            $res = $session->get('sessionObj')->confirmorderform();
            $response->setContent(json_encode($res));
            $response->setStatusCode(200);
        }
    }
    if ($request->getMethod() == 'DELETE') {           // delete queue, delete comment
        $response->setStatusCode(400);
    }
    if ($request->getMethod() == 'PUT') {              // enqueue, add comment
        $response->setStatusCode(400);
    }
} else {
    $redirect = new RedirectResponse($_SERVER['REQUEST_URI']);
}

// Do logging just before sending response?

$response->send();
