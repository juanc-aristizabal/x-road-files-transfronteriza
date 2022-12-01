#!/bin/bash

PATH_NAME_1=~/$XROAD_FOLDER/src/center-ui/app/controllers/configuration_management_controller.rb
PATH_NAME_2=~/$XROAD_FOLDER/src/center-service/app/models/configurations_generator.rb

cp ./configuration_management_controller.rb  PATH_NAME_1
cp ./configurations_generator.rb  PATH_NAME_2

if [ -f "$PATH_NAME_2" ]; then
    echo "everything's ok..."
else
    echo "$FILE does not exist."
fi

