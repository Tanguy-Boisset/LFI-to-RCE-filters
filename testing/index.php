<?php

echo "This app is vulnerable to LFI !! <br/><br/>";


include($_GET['file']);

echo "<br/><br/>Use 'file' parameter in GET request to get an LFI !";

?>