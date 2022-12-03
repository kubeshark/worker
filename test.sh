#!/bin/bash

go build -o worker .

sudo ./worker -i any
