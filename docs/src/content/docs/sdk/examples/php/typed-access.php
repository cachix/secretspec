<?php

// $resolved->fields() is a [SECRET_NAME => value] map; quicktype's `from`
// wants an object, so cast it.
$typed = Monosecret::from((object) $resolved->fields());
echo $typed->getDatabaseURL();
