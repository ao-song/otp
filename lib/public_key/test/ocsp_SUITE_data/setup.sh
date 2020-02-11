# Create folder structure and default files for root CA

mkdir -p CA/private
mkdir -p CA/newcerts
touch CA/index.txt
echo '00' > CA/serial

# Create the root CA