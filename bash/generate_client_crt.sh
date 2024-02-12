iccid=${1?param missing - collar iccid.}
path=${2:-"/crt/"}

mkdir -p ./$path/$iccid

openssl genpkey -algorithm RSA -out ./$path/$iccid/client.key

openssl rsa -pubout -in ./$path/$iccid/client.key -out ./$path/$iccid/client.pub

openssl req -new -key ./$path/$iccid/client.key -subj "/CN=$iccid" -out ./$path/$iccid/client.csr

openssl x509 -req -in ./$path/$iccid/client.csr -CA ./ca/ca.crt -CAkey ./ca/ca.key -out ./$path/$iccid/client.crt -days 365

echo $iccid