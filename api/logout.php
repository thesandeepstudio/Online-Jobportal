<?php
session_start();
session_unset();
session_destroy();
echo json_encode(["status" => true, "message" => "Logged out"]);
?>