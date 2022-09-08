<?php
 $CSRFURL = "http://" . $_SERVER['HTTP_HOST'] . "/csrf.php";
 echo $CSRFURL;

 $AUTHURL = "http://uauth.challs.teamitaly.eu/auth?redirect_uri=http%3A%2F%2Fsaffron.challs.teamitaly.eu%2Fcb&response_type=token";
 echo $AUTHURL;
?>

<script>
    window.open('<?php echo $CSRFURL;?>')
    document.location = '<?php echo $AUTHURL;?>'
</script>