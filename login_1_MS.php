/** 
* CHANGELOG:
*----------------------------------------------------------------------------
* Version | Date       | Author              | Description
* ----------------------------------------------------------------------------
* ----------------------------------------------------------------------------
* 1.1     | 2026-05-15 | MS15052026          | Added Device Verification logic            
*         |            |                     | To detect known and new login                    
*         |            |                     | devices also verify and manage 
*         |            |                     | those devices through tbl_login   
*-----------------------------------------------------------------------------
*/
<!DOCTYPE html>
<!---- for browser version check----------------------------->
<script>
var browser = '';
var browserVersion = 0;

if (/MSIE (\d+\.\d+);/.test(navigator.userAgent)) {
    browser = 'MSIE';
} 
if(browserVersion === 0){
    browserVersion = parseFloat(new Number(RegExp.$1));
}
//alert(browser + "*" + browserVersion);
if(browserVersion > 0 && browserVersion < 9){
 //alert('We do not support Internet explorer browser below version 9. We recommend to switch to latest version of Google chrome for better experience.');
 window.location.reload("error_page");
}
</script>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <title>GPS | Sign In</title>
  <meta content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" name="viewport">
  <meta http-equiv="X-UA-Compatible" content="IE=11"/>
  <meta http-equiv="X-UA-Compatible" content="IE=10"/>
  <meta http-equiv="X-UA-Compatible" content="IE=9"/>
  <meta http-equiv="X-UA-Compatible" content="IE=8"/>
  <link rel="stylesheet" href="css/PSnnect.min.css">
  <link rel="stylesheet" href="css/PSPanel.css">

<!--  <link rel="stylesheet" href="css/loader.css"> -->
  <!--[if lt IE 9]>
  <script src="https://oss.maxcdn.com/html5shiv/3.7.3/html5shiv.min.js"></script>
  <script src="https://oss.maxcdn.com/respond/1.4.2/respond.min.js"></script>
  <![endif]-->
  <link rel="apple-touch-icon-precomposed" sizes="114x114" href="img/fevicon.ico">
  <link rel="apple-touch-icon-precomposed" sizes="72x72" href="img/fevicon.ico">
  <link rel="apple-touch-icon-precomposed" href="img/fevicon.ico">
  <link rel="shortcut icon" href="img/fevicon.ico">


<script src="js/PSjquery.min.js"></script>
<script src="js/PSnnect.min.js"></script>
<script src="js/PSnnectValidator.min.js"></script>
<script src="js/SignInVal.js"></script>
<link rel="stylesheet" href="css/sweetalert.css">
<script src="js/sweetalert.min.js"></script>
<style>
html{background-image: linear-gradient(to bottom right, #BB133E, #002e5b);}
body{background:#ffffff00;/*background-color: rgba(0, 0, 0, 0.2);*/}
.clearable__clear{position: absolute;top: 6px;}
/*.has-success .input-group-addon{color: #002e5b!important;background:#fff!important;}*/
:focus-visible {outline: -webkit-focus-ring-color auto 0px!important;}
input:-internal-autofill-selected {background-color: #fff !important;}
.wrapper-login button[type=button], .wrapper-login button[type=submit], .wrapper-login button[type=reset]{
	-webkit-box-shadow: 2px 2px 3px #002e5b;box-shadow: 2px 2px 3px #002e5b;}
.wrapper-login a {font-size: 14px;}	
.ml10{margin-left: 10px;}
.mt10{margin-top: 10px;}
.f_wid{width:100%;}
.user{background: #ffffff;border: 3px solid #002e5b;border-radius: 15px;padding: 2px 0px;}
.user:hover {box-shadow: 6px 6px 8px lightgrey;}
.bor{border-bottom: 0px solid #28648A!important;width: 100%;border-top-right-radius: 9px;border-bottom-right-radius: 9px;}
.wrapper-login input[type=text], .wrapper-login input[type=password]{background-color: #e8f0fe!important;}
.p0{padding:0px;}
.pr0{padding-right:0px;}
.input-group .input-group-addon:hover{font-size:18px;}
.fourth:hover{box-shadow:2px 2px 4px #002e5b!important;font-size:14px!important;}

/*Start Linkdin*/
.linkedin{background: #3c8dbc;border-top-left-radius: 10%;border-bottom-left-radius: 10%;color: #fff;height: 30px;width:30px;float:right;
          box-shadow: -6px 6px 7px #d2d6de;}
.linkedin:hover{width: 50px!important;border-top-left-radius: 10%;border-bottom-left-radius: 10%;border-right: none;transition: width 2s, transform 2s;}
/*End Linkdin*/
</style>
</head>

<body class="hold-transition skin-yellow sidebar-mini" style="background-color: rgba(0, 0, 0, 0);">
<div id="show">
        <img src="img/tilt.png" style="width:80px;">
        <h6>We don't support Mobile view for best experience go to Desktop view</h6>
</div>

<?php

header("X-XSS-Protection: 1; mode=block");
// ini_set('header always set x-frame-options',"DENY");
error_reporting(1);
include_once "config.php";
require_once 'device_fingerprint.php'; // MS15052026 - ADDED DEVICE FINGERPRINTING FUNCTIONS
session_start();
// if(isset($_SESSION['email']))
// {
//   header('Location: inventory_layout');
//   exit();
//   }

// MS15052026 - ADDED FUNCTION TO GET BROWSER NAME
function getBrowserName($userAgent) {
    if(stripos($userAgent, 'Edg') !== false) return 'Edge';
    if(stripos($userAgent, 'OPR') !== false || stripos($userAgent, 'Opera') !== false) return 'Opera';
    if(stripos($userAgent, 'Chrome') !== false && stripos($userAgent, 'Edge') === false) return 'Chrome';
    if(stripos($userAgent, 'Firefox') !== false) return 'Firefox';
    if(stripos($userAgent, 'Safari') !== false && stripos($userAgent, 'Chrome') === false) return 'Safari';
    if(stripos($userAgent, 'MSIE') !== false || stripos($userAgent, 'Trident') !== false) return 'Internet Explorer';
    return 'Unknown Browser';
}
// MS15052026 - END GET BROWSER NAME

for ($i = 1; $i <= 36; $i++) 
  {
    $months[] = date("Y-m", strtotime( date( 'Y-m-01' )." -$i months"));
  }

  $DATE1 = $months[10]; //Start Date
  $DATE2 = date('Y-m'); //End Date

  $DATE4 = $months[34]; //Start Date for timeline graph 3 years


unset($_SESSION['count']);
$msg="";$Emailmsg=''; $passwordmsg='';
if(isset($_POST['but_submit'])){
    $agent               =$_SERVER['HTTP_USER_AGENT'];
    $browserName         = getBrowserName($agent);        // MS15052026 - Added to get exact browser name.
    $ipAddress           =$_SERVER['REMOTE_ADDR']; 
    $host_name           =gethostname();
    $email               =trim($_POST['txt_uname']);
    $pass                =trim($_POST['txt_pwd']);
     $postemail           =htmlspecialchars($email,ENT_QUOTES, 'UTF-8');//echo $postemail;exit;
    $password            =htmlspecialchars($pass,ENT_QUOTES, 'UTF-8');
    $encrypted_string = md5($password);
    $date             =date('Y-m-d H:i:s');
  if($postemail==''){
       $Emailmsg="User id can not be left blank";
   }
 if($password == ''){
    $passwordmsg="Password id can not be left blank";
  }
    if ($postemail != "" && $password != ""){
        // MS15052026 - Commented Below query and added new to read Fingerprint from DB.
        //$sql_query = "select count(*) as cntUser,UserGroup,id,fullName,vchPassword,email,LastName,companyId,userType,state,portfolioCode,role,productCode,firmCode,clientCode,loginStatus,createdAt,Check_multiple_status,Passexpdate,IPaddress,AuthorisedFlag,active_inactive_status,bit_deleted_flag from tbl_login where email='".$postemail."' and bit_deleted_flag=0 and  vchPassword !='' and company_status!=4 group by id,fullName,vchPassword,email,LastName,companyId,userType,state,portfolioCode,role,productCode,firmCode,clientCode,loginStatus,createdAt,Check_multiple_status,Passexpdate,IPaddress,AuthorisedFlag,active_inactive_status,bit_deleted_flag";//echo $sql_query;exit;
        $sql_query = "select count(*) as cntUser,UserGroup,id,fullName,vchPassword,email,LastName,companyId,userType,state,portfolioCode,role,productCode,firmCode,clientCode,loginStatus,createdAt,Check_multiple_status,Passexpdate,IPaddress,AuthorisedFlag,active_inactive_status,bit_deleted_flag,FPrint from tbl_login where email='".$postemail."' and bit_deleted_flag=0 and  vchPassword !='' and company_status!=4 group by id,fullName,vchPassword,email,LastName,companyId,userType,state,portfolioCode,role,productCode,firmCode,clientCode,loginStatus,createdAt,Check_multiple_status,Passexpdate,IPaddress,AuthorisedFlag,active_inactive_status,bit_deleted_flag";//echo $sql_query;exit;

            $result = mysqli_query($conn,$sql_query);
            $row = mysqli_fetch_array($result);
            $count          = $row['cntUser'];
            $loginStatus    = $row['loginStatus'];
            $userType       =$row['userType'];
            $state          =$row['state'];
            $portfolioCode  =$row['portfolioCode'];
            $role           =$row['role'];
            $role1          =$row['role'];
            $fullName       =$row['fullName'];
            $email          =$row['email'];
            $userloginType  =$row['userloginType'];
            $productCode    =$row['productCode'];
            $firmCode       =$row['firmCode'];
            $clientCode     =$row['clientCode'];
            $companyId      =$row['companyId'];
            $LastName       =$row['LastName'];
            $passwordDB     =$row['vchPassword'];
            $id             =$row['id'];
            $dateex         = DateTime::createFromFormat('m-d-Y', $row['Passexpdate']);
            $Passexpdate     =strtotime($dateex->format('Y-m-d'));
            //$IPaddress      =explode(',',$row['IPaddress']); // MS15052026
            $IPaddress = !empty($row['FPrint']) ? explode(',', $row['FPrint']) : []; //MS15052026 - CHANGED TO EXPLODE FPrint FIELD INTO ARRAY OF DEVICES (IP/UA/TOKEN/FP)
            $countIPaddress =count($IPaddress);//echo $countmacaddress;exit;
            $AuthorisedFlag =$row['AuthorisedFlag'];
            $active_inactive_status=$row['active_inactive_status'];

            
            $_SESSION['id'] = $id;
           if($role==6 || $role==10){
              $role=6;
            }else {
              $role=$role;
            }

//print_r($mac);exit;

            if(strtolower($postemail)!=strtolower($email)){
            $Emailmsg="Invalid userid";
            }
            else  if($encrypted_string!= $passwordDB){
              $passwordmsg="Invalid Password";
            }
         // else if($countIPaddress ==5 && (!in_array($ipAddress, $IPaddress))){
         //   $unauthusermore="More than 5 devices exceeded, cannot be authenticated. Please contact admin.";
         //   $updatestatus="UPDATE tbl_login SET AuthorisedFlag=1  WHERE  email='".$email."'";
         //    mysqli_query($conn,$updatestatus);
         //  }
          //  else if(!in_array($ipAddress, $IPaddress)){
          //   $unauthuser="Device not verified, please check email for verification code.";
            
          // }
else
{
// MS15052026 - Start Modification
// ===== DEVICE CHECK =====
 
$deviceVerified = false;
$cookieToken    = $_COOKIE['device_token'] ?? '';
$fp             = DeviceFingerprint::fromPost();   // fingerprint from hidden input
 
$deviceEntries  = [];   // array of parsed entry arrays
$rawEntries     = [];   // array of raw entry strings (for re-saving)
$deviceCount    = 0;
 
if (!empty($row['FPrint'])) {
 
    // Split multiple devices by ';;'  (never appears in IP/UA/token/FP)
    $rawEntries  = array_filter(array_map('trim', explode(';;', $row['FPrint'])));
    $deviceCount = count($rawEntries);
    //$deviceCount = max(0, count($rawEntries) - 1);
    //print_r($rawEntries); // debug
    //echo "Device count: $deviceCount\n"; // debug
    //exit; // debug
 
    foreach ($rawEntries as $entry) {
 
        // Split fields by '|'
        $parts = explode('|', $entry);
 
        // Format: IP | Label | UA | Token | FP
        $storedToken = trim($parts[3] ?? '');
        $storedFP    = trim($parts[4] ?? '');
 
        //  Match 1: fingerprint (works even after cookie cleared) 
        $postedFP = trim($_POST['device_fingerprint'] ?? '');
        if ($postedFP !== '' && $storedFP !== '' && hash_equals($storedFP, $postedFP)) {
            $deviceVerified = true;
            // Re-issue cookie silently so it stays fresh
            if (empty($cookieToken)) {
                setcookie('device_token', $storedToken, time() + 86400 * 365, '/');
            }
            break;
        }
 
        //  Match 2: cookie token 
        if (!empty($cookieToken) && $storedToken !== '' && hash_equals($storedToken, $cookieToken)) {
            $deviceVerified = true;
            break;
        }
 
        //  Match 3: IP + UA fallback (for entries with no FP yet) 
        $storedIP = trim($parts[0] ?? '');
        $storedUA = trim($parts[2] ?? '');
        if (empty($cookieToken) && $storedFP === ''
            && $storedIP === $ipAddress && $storedUA === $agent) {
            $deviceVerified = true;
            break;
        }
    }
}
 
//  NOT VERIFIED - send to OTP page
if (!$deviceVerified) {
 
    //$otp = rand(100000, 999999);
   // $_SESSION['otp']      = $otp;
    //$_SESSION['otp_time'] = time();
 
    /* mysqli_query($conn, "UPDATE tbl_login
        SET OTP      = '" . mysqli_real_escape_string($conn, $otp) . "',
            OTPTime  = '" . date('Y-m-d H:i:s') . "',
            OTPCount = '$deviceCount'
        WHERE id = " . $id); */
 
    echo "<script>alert('Your OTP is: $otp');</script>"; // remove in production
 
    $_SESSION['temp_user_id']         = $id;
    $_SESSION['new_device_ip']        = $ipAddress;
    $_SESSION['new_device_name']      = $browserName;
    $_SESSION['device_count']         = $deviceCount;
    $_SESSION['device_limit_reached'] = ($deviceCount >= 5);
 
    // Pass fingerprint to verify_device_MS.php
    DeviceFingerprint::saveToSession($fp);
 
    header("Location: verify_device_MS.php");
    //header("Location: inventory_layout"); // added this line to direct control to inventory_layout after OTP verification.
    exit();
}
 
// ===== DEVICE CHECK END =====
// MS15052026 - END Modification
    $_SESSION['email']        = $email;
    $_SESSION['userType']     = $userType;
    $_SESSION['state']        = $state;
    $_SESSION['portfolioCode']= $portfolioCode;
    $_SESSION['role']         = $role;
    $_SESSION['role60r10']    = $role1;
    $_SESSION['fullName']     = $fullName;
    $_SESSION['userloginType']= $userloginType;
    $_SESSION['productCode']  = $productCode;
    $_SESSION['firmCode']     = $firmCode;
    $_SESSION['clientCode']   = $clientCode;
    $_SESSION['companyId']    = $companyId;
    $_SESSION['LastName']     = $LastName;
    $_SESSION['id']           = $id;
    $_SESSION['UserGroup']    = $row['UserGroup'];
    $_SESSION['phoneNo']      = $row['phoneNo'];
    $_SESSION['timeout']      = time();
    $_SESSION['firmCodenew']     = $firmCode;
    $_SESSION['clientCodenew']   = $clientCode;


    $_SESSION['AACA_RCVD_BATCH_FROM'] = $DATE1;
    $_SESSION['AACA_RCVD_BATCH_END'] = $DATE2;
    $_SESSION['AACA_RCVD_BATCH_FROM_PIE'] = '2002-01';
    $_SESSION['AACA_RCVD_BATCH_END_PIE'] = $DATE2;

    $_SESSION['SETLMNT_BATCH_FROM'] = $DATE1;
    $_SESSION['SETLMNT_BATCH_END'] = $DATE2;

    $_SESSION['AACA_RCVD_BATCH_FROM_TIMELINE'] = $DATE4;
    $_SESSION['AACA_RCVD_BATCH_END_TIMELINE'] = $DATE2;


    $eulaQue="Select * from MANAGE_EULA where UserId=".$id."";
    $eularesult = mysqli_query($conn,$eulaQue);
    $roweula = mysqli_fetch_array($eularesult);
    $eulaStatus= $roweula['EulaStatus'];
    $euladaydate=strtotime(date('Y-m-d',strtotime($roweula['EulaDate'])));
    $currentDate=strtotime(date('Y-m-d'));
    $logindatediff=($currentDate - $euladaydate)/60/60/24;

    $eulayeardate     =strtotime(date('Y-m-d',strtotime($roweula['createdAt'])));
    $logindateyeardiff=($currentDate - $eulayeardate)/60/60/24;
    $passexpday       =($currentDate - $Passexpdate)/60/60/24;

    $countQuery="SELECT count(1) as Check_multiple_status  from tbl_login where  bit_deleted_flag=0 and email='".$postemail."'";//echo $countQuery;exit;
    $rescountQuery=mysqli_query($conn,$countQuery); 
    $fetchrescountQuery=mysqli_fetch_assoc($rescountQuery);

// if($row['bit_deleted_flag']!=$active_inactive_status){
//   $passwordmsg="Please authorise yourself";
//   }  

    
  if($fetchrescountQuery['Check_multiple_status']>=1 && $active_inactive_status==1){
$passwordmsg="Please authorise yourself";
}  
else if($passexpday>=90 && $fetchrescountQuery['Check_multiple_status']>=1){
   header('Location: Passexp');
}else if($logindateyeardiff >= 366 && $fetchrescountQuery['Check_multiple_status']>=1){
        header('Location: EULA?val=1');
 }


else if($count > 0 && $eulaStatus==1 && $logindatediff <90   && $fetchrescountQuery['Check_multiple_status']>=1){//$loginStatus==1 && 
   $date=date('Y-m-d H:i:s');
   $eulaloginDetails = "UPDATE MANAGE_EULA SET EulaDate='". $date."' WHERE UserId=".$id."" ;
   $eulaupdate = mysqli_query($conn,$eulaloginDetails);
  $qryloginDetails = "INSERT INTO logged_in_logs(`userName`,`emailId`,`ipAddress`,`browserDetails`,`LoggedinWith`) VALUES ('$fullName ','$email','$ipAddress','$agent','$host_name')";
$insert = mysqli_query($conn,$qryloginDetails);
//header('Location: inventory_layout.php');

  /*to show path based on usertype and role*/
if($fetchrescountQuery['Check_multiple_status']>1){
     $_SESSION['email']        = $email;
     header('Location: loginnew');
  }
else if($_SESSION['role']==9){
  header('Location: judgment_layout');  
}else {
  if(isset($_SESSION['settlement_number']))
{
  header('Location: Settlement_Form/settlement-request');
}else if(isset($_SESSION['urlloc']))
{
  header('Location: mydownload');
}
else
{
   header('Location: inventory_layout');
 }
}

/*to show path based on usertype and role*/

}

else if($count > 0 && $eulaStatus==0  && $fetchrescountQuery['Check_multiple_status']>=1){//$loginStatus==1 && 
  header('Location: EULA');
}
else if($count > 0 && $eulaStatus==1 &&  $logindatediff >=90  && $fetchrescountQuery['Check_multiple_status']>=1){//$loginStatus==1 && 
  header('Location: EULA');
}
// else if($loginStatus==0 && $count>0  && $row['Check_multiple_status']==0){ 
//   $_SESSION['email'] = $email;

// header('Location: changepassword');
// }


    else { 
        $msg="Invalid userid or password";
    }
}   

    }

}?>

<!--<div class="loader"></div> -->
 
<div class="wrapper-login fadeInDown login-section" id="warning-message1">
    
  <div id="formContent" class="modal-dialog">
      
    <div class="formHeader clearfix">
        <div class="col-sm-12 mar20B">
            <div class="fadeIn first">
              <!--<img src="assets/gallery/ko-logo.png" class="img-resposnive login-logo" alt="User Icon"/><br>-->
                <div class="col-sm-6">
                    <img src="img/aaca-net.png" class="img-resposnive login-logo  ml10 f_wid" alt="aacanet"/>
                </div>
                <div class="col-sm-6 text-center">
                    <!--<h1>PIPEWAY</h1>-->
                    <img src="img/pipeway-logo.gif" class="img-resposnive login-logo  mt10 f_wid" alt="aacanet"/>
                </div>
            </div>
        </div>
    
    <div class="col-sm-12">
        <form action="" id="loginForm" method="post" autocomplete="off">
          <input type="hidden" id="device_fingerprint" name="device_fingerprint" value=""> <!-- MS15052026 -->
           <span style="color:red"><?php echo $unauthuser;?></span>
         <span style="color:red"><?php echo $unauthusermore;?></span>
        <div class="form-group clearfix">
         <div class="input-group fadeIn second user">
          <span class="input-group-addon" style="background-color: #eeeeee0a;
    border-bottom: 0px solid #28648A;color: #012f5c;transition: all .5s ease;background-color: rgba(0, 0, 0, 0);border-radius:10px;"><i class="fa fa-user" aria-hidden="true"></i></span> 
  
            <span class="clearable">
            <input type="text" class="bor" id="email" name="txt_uname" placeholder="User name" maxlength="50" value="<?php echo isset($_POST["txt_uname"]) ? $_POST["txt_uname"] : ''; ?>" / autofocus>
              <i class="clearable__clear" style="display: inline;">&times;</i>
          </span>
          </div>
          <span style="color:red;font-size: 11px;margin-left: 45px;margin-bottom:0px;"><?php echo $Emailmsg;?></span>
        </div>
        <div class="form-group clearfix">
         <div class="input-group fadeIn third user">
           <span class="input-group-addon" style="background-color: #eeeeee0a;
    border-bottom: 0px solid #28648A;color: #012f5c;transition: all .5s ease;background-color: rgba(0, 0, 0, 0);border-radius:10px;"><i class="fa fa-lock" aria-hidden="true"></i></span> 
<!--           <input type="password" id="password" class="" name="password" placeholder="Password"> -->
            <span class="clearable">
           <input type="password" class="bor" id="password" name="txt_pwd" placeholder="Password" value="<?php echo isset($_POST["txt_pwd"]) ? $_POST["txt_pwd"] : ''; ?>"/ maxlength="20" autofocus>
             <i class="clearable__clear" style="display: inline;">&times;</i>
         </span>
        </div>
        <p style="color:red;font-size: 11px;margin-left: 45px;margin-bottom:0px;"><?php echo $passwordmsg;?></p>
        <?php if($Emailmsg!='' || $passwordmsg!='') {?>
        <p style="color:#607D8B;font-size: 11px;width: 100%;margin-left: 8px;margin-top:5px;">Please enter your user name and password. If you do not have a user name and password, please contact your company's Pipeway Administrator.  If you forgot your user name or password, contact your company's Pipeway Administrator or use the link below. </p>
      <?php }?>
        </div>
       <!--   <span class="loginmsg"><?php //echo $msg;?></span> -->
        <div class="form-group clearfix">
          <button type="submit" class="fadeIn fourth f_wid" name="but_submit" id="but_submit" style="border-radius: 15px;background: #002e5b;"><i class="fa fa-key" aria-hidden="true"></i> Log In</button>

        <!--   <input type="submit" class="textbox" value="Login" name="but_submit" id="but_submit"  /></br></br> 
               <a href="forgotpassword.php" id="forgotpass"><b>Forgot password ?</b></a>  -->
          
          <!--<br><a class="underlineHover fadeIn fourth" id="forgotpass" href="forgotpassword.php">Forgot Password?</a>--->
        </div>
		<div class="col-md-12" style="text-align:center;">
		<a class="underlineHover fadeIn fourth" id="forgotpass" href="forgotpassword">Forgot Password?</a>
		</div>
    </form>
    </div>
      
    </div>
    
<!--    <div id="formFooter">
      <a class="underlineHover fadeIn fourth" href="register.html#">Register here</a>
    </div> -->    
  <section>
	  <div class="col-sm-8 p0"></div>
	  <div class="col-sm-4 p0" style="position: relative;bottom: 65px;">
        <div class="linkedin" style="" title="Connect wih us!">
          <a href="https://www.linkedin.com/company/aacanet-inc." target="blank"  title="Connect with us!" style="color:#fff;">
          <i class="fa fa-linkedin fa-x" style="padding: 8px 10px;"></i></a>
        </div>
	  </div>
	</section>
   </div>  
 </div>
</body>
<script type="text/javascript">
  $("#password").keypress(function(event) { 
      if (event.keyCode === 13) { 
          $("#but_submit").click(); 
      } 
  });
  $(document).ready(function(){
    $(".clearable").each(function() {
  
  var $inp = $(this).find("input:text"),
      $cle = $(this).find(".clearable__clear");

  $inp.on("input", function(){
    $cle.toggle(!!this.value);
  });
  
  $cle.on("touchstart click", function(e) {
    e.preventDefault();
    $inp.val("").trigger("input");
  });
  
});
 $(".clearable").each(function() {
  
  var $inp = $(this).find("input:password"),
      $cle = $(this).find(".clearable__clear");

  $inp.on("input", function(){
    $cle.toggle(!!this.value);
  });
  
  $cle.on("touchstart click", function(e) {
    e.preventDefault();
    $inp.val("").trigger("input");
  });
  
});
  }) 
  var auth ='<?php echo $unauthuser;?>';
if(auth!=''){
  var email='<?php echo $_POST['txt_uname'];?>';
  $.ajax({
  type: "GET",
  url: "authenticate.php",
  data:{email:email},
   success: function(data){
 
   }
 });
}
// MS15052026 - START ADDED DEVICE FINGERPRINTING INITIALIZATION 
</script> 
<script src="js/DeviceFingerprint.js"></script>
     <script>
       document.addEventListener('DOMContentLoaded', function () {
           DeviceFingerprint.init('device_fingerprint');
       });
     </script>    
<!-- MS15052026 - END ADDED DEVICE FINGERPRINTING INITIALIZATION -->
<?php
/* Start:Change log sweet alert  by puja kuamri on dt-061021 */
 if(isset($_SESSION['forgototp']))
  {?>
   <script> swal({title: "",
                text: "OTP has been sent to your email id",
                timer: 3000,
                showConfirmButton: false,
                type: 'success'
              });  </script>
 <?php }
 unset($_SESSION['forgototp']);
  if(isset($_SESSION['resetforgotpass']))
  {?>
   <script> swal({title: "",
                text: "Password created successfully",
                timer: 3000,
                showConfirmButton: false,
                type: 'success'
              });  </script>
 <?php }
 unset($_SESSION['resetforgotpass']);


   if(isset($_SESSION['authenticate']))
  {?>
   <script> swal({title: "",
                text: "User authenticated successfully",
                timer: 3000,
                showConfirmButton: false,
                type: 'success'
              });  </script>
 <?php }
 unset($_SESSION['authenticate']);
 if(isset($_SESSION['changepass'])){
  unset($_SESSION['email']);
  ?>
   <script> swal({title: "",
                text: "Password changed successfully",
                timer: 3000,
                showConfirmButton: false,
                type: 'success'
              });  </script>
 <?php }
 unset($_SESSION['changepass']);
 /*End: Change log sweet alert  by puja kuamri on dt-061021*/

if($_SESSION['role']==9){
  header('Location: judgment_layout');  
}else {
if(isset($_SESSION['settlement_number']))
{
header('Location: Settlement_Form/settlement-request');
}
else
{
  header('Location: inventory_layout');
 }
}


//$_SESSION["login_time_stamp"] = time(); 

?>



</html>