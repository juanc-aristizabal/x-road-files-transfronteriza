#!/bin/bash

PATH_NAME=~/$XROAD_FOLDER/src/center-ui/app/controllers/configuration_management_controller.rb


cp ./files/configuration_management_controller.rb  $PATH_NAME

if [ -f "$PATH_NAME" ]; then
    echo ""
    echo "everything's ok, life is good..."
    echo ""
else
    echo "$PATH_NAME does not exist."
fi


