cd /var/www
rm -R vulnshop
git clone https://github.com/SilentProcess87/vulnshop-multi-cloud.git vulnshop
cp vulnshop.backup1/fix-deployment.sh vulnshop
chmod -R 777 vulnshop
cd vulnshop 
./fix-deployment.sh