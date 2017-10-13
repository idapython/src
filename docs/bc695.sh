#!/bin/sh
TARGET_DIR=../../../../www/www.hex-rays.com/public_html/hex-rays/products/ida/7.0/docs
TARGET_FILE=$TARGET_DIR/idapython_backward_compat_695.html
p4 edit $TARGET_FILE
echo \<html\>\<head\> > $TARGET_FILE
echo \<link type="text/css" rel="stylesheet" href="../../../../style.css" /\> >> $TARGET_FILE
echo \<link type="text/css" rel="stylesheet" href="style.css" /\> >> $TARGET_FILE
echo \</head\>\<body\> >> $TARGET_FILE
markdown bc695.md >> $TARGET_FILE
echo \</body\>\</html\> >> $TARGET_FILE
p4 revert -a $TARGET_FILE
