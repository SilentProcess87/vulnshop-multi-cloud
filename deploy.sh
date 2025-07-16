cd /var/www
rm -R vulnshop
git clone https://github.com/SilentProcess87/vulnshop-multi-cloud.git vulnshop

chmod -R 777 vulnshop
cd vulnshop 
chmod +x fix-deployment.sh
./fix-deployment.sh