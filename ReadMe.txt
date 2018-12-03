The code requires the following packages and libraries installed:
- mysql-proxy 0.8.1
- mysql 14.14
- lua 5.1
- TFHE (https://tfhe.github.io/tfhe/)

Tested on Ubuntu 16.04, not tested on different environments.

You first need to compile tfhelib.cpp into tfhelib.so it can be imported by wrapper.lua.


//Use the following command to compile tfhelib.cpp into tfhelib.so:

g++ -ansi -shared -fPIC -llua5.1 -I/usr/include/lua5.1/ -Wall -O3 -o tfhelib.so tfhelib.cpp -ltfhe-spqlios-fma -std=gnu++11

where -llua5.1 flag must match the version of Lua script you are using and -I/usr/include/lua5.1/ should specify the path your lua is located.


//You must also run the following command or place the following command in your .bashrc so wrapper.lua can import PROXYDIR environment variable:

export PROXYDIR=/full/path/to/mysqlproxy_product



//After that, run the following command to execute mysql-proxy:

mysql-proxy --proxy-lua-script=$PROXYDIR2/wrapper.lua --proxy-address=127.0.0.1:3308 --proxy-backend-addresses=localhost:3306 --plugins=proxy --event-threads=4  --max-open-files=1024

Here, 3308 can be any port number the proxy will be listening to.



//You can connect to mysql-proxy by running the following command:

mysql -u root -pletmein -h 127.0.0.1 -P 3308

where -pletmein should specify the password you set for mysql.




The proxy supports all default commands supported by mysql but it also supports the following commands:

//To generate secret keys and cloud keys that will be used:

generate keys;


//To create tables that will be used to store encrypted integers:

create table ciphertext;

//To drop tables that are used to store encrypted integers:

drop table ciphertext;

//To insert plaintext which is a type of integer into database in encrypted form.
//userid is the id of the user who posesses plaintext.
//plaintext is a plaintext value of the integer that is being stored.

insert into ciphertext values(userid, plaintext);


//To create tables that will be used to store encrypted doubles:

create table ciphertextdouble;


//To drop tables that are used to store encrypted doubles:

drop table ciphertextdouble;


//To insert plaintext which is a type of double into database in encrypted form.
//userid is the id of the user who posesses plaintext.
//plaintext is a plaintext value of the double that is being stored.

insert into ciphertextdouble values(userid, plaintext);


//To show sizes of the current tables:

show tablesizes;

//To retrieve stored encrypted integer value in plaintext format which belong to the user with userid:

select * from ciphertext where userid=int;


//To retrieve stored encrypted double value in plaintext format which belong to the user with userid:

select * from ciphertextdouble where userid=int;



select * from mysql.func;
drop function comparison;

//copy to plugin directory
sudo cp tfhe_udf_cpp.so /usr/local/mysql/lib/plugin

g++ -shared -o tfhe_udf_cpp.so tfhe_udf.cpp -L/usr/lib/x86_64-linux-gnu -lmysqlclient -lpthread -lz -lm -lrt -ldl -I/usr/include/mysql -fPIC -ltfhe-spqlios-fma -std=gnu++11


gcc -shared -o tfhe_udf.so tfhe_udf.c -L/usr/lib/x86_64-linux-gnu -lmysqlclient -lpthread -lz -lm -lrt -ldl -I/usr/include/mysql -fPIC -std=gnu99
