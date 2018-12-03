directorypath = os.getenv("PROXYDIR2")

package.cpath = directorypath .. "/tfhelib.so"

numbits = 16

require "mylib"

function string.starts(String,Start)
    return string.sub(String,1,string.len(Start))==Start
end

function file_exists(file)
    local f = io.open(file, "rb")
    if f then f:close() end
    return f ~= nil
  end
  

function lines_from(file)
    if not file_exists(file) then return {} end
    lines = {}
    for line in io.lines(file) do 
        lines[#lines + 1] = line
    end
    return lines
end

-- syntax:
-- id: id of the individual, value: actual value to be encrypted
-- insert into ciphertext values(userid int, value int);
-- int will be encrypted and stored into ciphertext_biti tables
function insert_handler(query)

    local array = {}
    for capture in string.gmatch(query, "-?%d+") do
        table.insert(array, capture)
    end

    id = array[1]
    value = array[2]

    mylib.HOMencrypt(value)
    
    file = 'encryptedInteger.txt'
    lines = lines_from(file)

    linenumber = 1

    for i=0,15,1
        do
        modifiedquery = "insert into ciphertext_bit" .. i .. " values("
        
        -- whose data this is
        modifiedquery = modifiedquery .. id .. ", "

        for j = 0,501,1
        do
            if j == 501 then
                modifiedquery = modifiedquery .. lines[linenumber] .. ")"
                linenumber = linenumber + 1
                break
            end
            modifiedquery = modifiedquery .. lines[linenumber] .. ", "
            linenumber = linenumber + 1
            
        end
        if i == 15 then
            proxy.queries:append(-1, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
        else
            proxy.queries:append(3, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
        end
    end            

    os.remove("encryptedInteger.txt")

    return proxy.PROXY_SEND_QUERY

end

-- syntax:
-- userid: id of the individual, value: actual value to be encrypted
-- insert into ciphertextdouble values(userid int, value double);
function insertdouble_handler(query)
    local array = {}
    for capture in string.gmatch(query, '%d[%d.]*') do
        table.insert(array, capture)
    end

    userid = array[1]
    value = array[2]
    
    mylib.HOMencryptdouble(value)
    
    file = 'encrypteddouble.txt'
    lines = lines_from(file)

    linenumber = 1

    for i=0,15,1
        do
        modifiedquery = "insert into ciphertext_integer_bit" .. i .. " values("
        
        -- whose data this is
        modifiedquery = modifiedquery .. userid .. ", "

        for j = 0,501,1
        do
            if j == 501 then
                modifiedquery = modifiedquery .. lines[linenumber] .. ")"
                linenumber = linenumber + 1
                break
            end
            modifiedquery = modifiedquery .. lines[linenumber] .. ", "
            linenumber = linenumber + 1
            
        end
        proxy.queries:append(3, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
        
    end        
    for i=0,15,1
        do
        modifiedquery = "insert into ciphertext_fraction_bit" .. i .. " values("
        
        -- whose data this is
        modifiedquery = modifiedquery .. userid .. ", "

        for j = 0,501,1
        do
            if j == 501 then
                modifiedquery = modifiedquery .. lines[linenumber] .. ")"
                linenumber = linenumber + 1
                break
            end
            modifiedquery = modifiedquery .. lines[linenumber] .. ", "
            linenumber = linenumber + 1
            
        end
        if i == 15 then
            proxy.queries:append(-1, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
        else
            proxy.queries:append(3, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
        end
    end            
    os.remove("encrypteddouble.txt")
    return proxy.PROXY_SEND_QUERY

end


function size_handler(query)
    modifiedquery = "SELECT table_schema as `Database`, table_name AS `Table`, round(((data_length + index_length) / 1024 / 1024), 2) `Size in MB` FROM information_schema.TABLES ORDER BY (data_length + index_length) DESC"
    proxy.queries:append(4, string.char(proxy.COM_QUERY) .. modifiedquery);
    return proxy.PROXY_SEND_QUERY
    
end

function drop_handler(query)
    for i=0,(numbits-1),1
        do
        modifiedquery = "drop table ciphertext_bit" .. i

        if i == (numbits-1) then
            proxy.queries:append(-1, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
        else
            proxy.queries:append(2, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
        end
    end            

    return proxy.PROXY_SEND_QUERY
end

-- asssumes the first field given in where clause is userid
function select_handler(query)
    local array = {}

    for capture in string.gmatch(query, '%d[%d.]*') do
        table.insert(array, capture)
    end

    userid = array[1]

    for i=0,(numbits-1),1
        do
        modifiedquery = "select * from ciphertext_bit" .. i .. " where userid = " .. userid

        proxy.queries:append((i+5), string.char(proxy.COM_QUERY) .. modifiedquery, {resultset_is_needed = true})
    end    


    return proxy.PROXY_SEND_QUERY
end

-- asssumes the first field given in where clause is userid
function selectdouble_handler(query)
    local array = {}
    for capture in string.gmatch(query, "%d+") do
        table.insert(array, capture)
    end

    id = array[1]

    for i=0,(numbits-1),1
        do
        modifiedquery = "select * from ciphertext_integer_bit" .. i .. " where userid = " .. id 

        proxy.queries:append((-5-i), string.char(proxy.COM_QUERY) .. modifiedquery, {resultset_is_needed = true})
    end    

    for i=0,(numbits-1),1
        do
        modifiedquery = "select * from ciphertext_fraction_bit" .. i .. " where userid = " .. id 

        proxy.queries:append((-6-(numbits-1)-i), string.char(proxy.COM_QUERY) .. modifiedquery, {resultset_is_needed = true})
    end    

    return proxy.PROXY_SEND_QUERY
end

function test_handler(query)
   
    modifiedquery = "select * from ciphertext_bit0" 

    proxy.queries:append(21, string.char(proxy.COM_QUERY) .. modifiedquery, {resultset_is_needed = true})

    return proxy.PROXY_SEND_QUERY
end


function createdouble_handler(query)

    for i=0,(numbits-1),1
        do
        -- integer bit0 contains the least significant bit
        -- fraction bit0 contains the most fignificant bit (1/2)
        modifiedquery = "create table ciphertext_integer_bit" .. i .. " ("
        -- whose data this is
        modifiedquery = modifiedquery .. "userid int, "

        for j = 0,499,1
        do
            modifiedquery = modifiedquery .. tostring(j) .. "th_a int, "
            if j == 499 then
                modifiedquery = modifiedquery .. "b_ int, " .. "variance double)" 
            
            end
        end
        proxy.queries:append(1, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
        
    end      
    
    for i=0,(numbits-1),1
        do
        -- integer bit0 contains the least significant bit
        -- fraction bit0 contains the most fignificant bit (1/2)
        modifiedquery = "create table ciphertext_fraction_bit" .. i .. " ("
        -- whose data this is
        modifiedquery = modifiedquery .. "userid int, "

        for j = 0,499,1
        do
            modifiedquery = modifiedquery .. tostring(j) .. "th_a int, "
            if j == 499 then
                modifiedquery = modifiedquery .. "b_ int, " .. "variance double)" 
            
            end
        end
        if i == (numbits-1) then
            proxy.queries:append(-1, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
        else
            proxy.queries:append(1, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
        end
    end   

    return proxy.PROXY_SEND_QUERY

end

function dropdouble_handler(query)

    for i=0,(numbits-1),1
        do
        modifiedquery = "drop table ciphertext_integer_bit" .. i 
        proxy.queries:append(1, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
    end      
    
    for i=0,(numbits-1),1
        do
        modifiedquery = "drop table ciphertext_fraction_bit" .. i 
        if i == (numbits-1) then
            proxy.queries:append(-1, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
        else
            proxy.queries:append(1, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
        end
    end   

    return proxy.PROXY_SEND_QUERY
end

function createudf_handler(query)
   
    modifiedquery = "drop function if exists metaphon" 
    proxy.queries:append(1, string.char(proxy.COM_QUERY) .. modifiedquery, {resultset_is_needed = true})
    modifiedquery = "drop function if exists avgcost" 
    proxy.queries:append(1, string.char(proxy.COM_QUERY) .. modifiedquery, {resultset_is_needed = true})
    modifiedquery = "drop function if exists comparison" 
    proxy.queries:append(1, string.char(proxy.COM_QUERY) .. modifiedquery, {resultset_is_needed = true})
    modifiedquery = "drop function if exists testfunction" 
    proxy.queries:append(1, string.char(proxy.COM_QUERY) .. modifiedquery, {resultset_is_needed = true})
    -- modifiedquery = "create function metaphon RETURNS STRING SONAME 'udf_example.so'"
    modifiedquery = "create function metaphon RETURNS STRING SONAME 'tfhe_udf_cpp.so'" 
    -- print("modifiedquery = " .. modifiedquery)
    proxy.queries:append(1, string.char(proxy.COM_QUERY) .. modifiedquery, {resultset_is_needed = true})
    -- modifiedquery = "create function avgcost RETURNS REAL SONAME 'udf_example.so'" 
    modifiedquery = "create function avgcost RETURNS REAL SONAME 'tfhe_udf_cpp.so'" 
    proxy.queries:append(1, string.char(proxy.COM_QUERY) .. modifiedquery, {resultset_is_needed = true})
    -- proxy.queries:append(1, string.char(proxy.COM_QUERY) .. modifiedquery, {resultset_is_needed = true})

    modifiedquery = "create function testfunction RETURNS INTEGER SONAME 'tfhe_udf_cpp.so'" 
    proxy.queries:append(1, string.char(proxy.COM_QUERY) .. modifiedquery, {resultset_is_needed = true})

    modifiedquery = "drop function if exists comparison" 
    proxy.queries:append(1, string.char(proxy.COM_QUERY) .. modifiedquery, {resultset_is_needed = true})
    modifiedquery = "create function comparison RETURNS INTEGER SONAME 'tfhe_udf_cpp.so'" 
    proxy.queries:append(-1, string.char(proxy.COM_QUERY) .. modifiedquery, {resultset_is_needed = true})

    return proxy.PROXY_SEND_QUERY
end

function insertcts_handler(query)

    for k=0,999,1
        do
        id = k
        value = k

        mylib.HOMencrypt(value)
        
        file = 'encryptedInteger.txt'
        lines = lines_from(file)

        linenumber = 1

        for i=0,15,1
            do
            modifiedquery = "insert into ciphertext_bit" .. i .. " values("
            
            -- whose data this is
            modifiedquery = modifiedquery .. id .. ", "

            for j = 0,501,1
            do
                if j == 501 then
                    modifiedquery = modifiedquery .. lines[linenumber] .. ")"
                    linenumber = linenumber + 1
                    break
                end
                modifiedquery = modifiedquery .. lines[linenumber] .. ", "
                linenumber = linenumber + 1
                
            end
            if ((i == 15) and (k == 999)) then
                proxy.queries:append(-1, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
            else
                proxy.queries:append(3, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
            end
        end            

        os.remove("encryptedInteger.txt")   
    end

    return proxy.PROXY_SEND_QUERY
end

function insertpts_handler(query)
    for k=0,999,1
        do
        id = k
        value = k

        modifiedquery = "insert into plaintext values("
        
        -- whose data this is
        modifiedquery = modifiedquery .. id .. ", "
        modifiedquery = modifiedquery .. value .. ")"

        if (k == 999) then
            proxy.queries:append(-1, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
        else
            proxy.queries:append(3, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
        end
          
    end

    return proxy.PROXY_SEND_QUERY
end

function read_query(packet)
    if packet:byte() == proxy.COM_QUERY then
        query = packet:sub(2)

        -- creates a table to store encrypted values
        -- this ciphertext contains 500 integer columns to represent a array
        --  1 int column to represent b 1 double column to represent current_variance
        if query == "create table ciphertext" then
            for i=0,(numbits-1),1
                do
                modifiedquery = "create table ciphertext_bit" .. i .. " ("
                -- whose data this is
                modifiedquery = modifiedquery .. "userid int, "

                for j = 0,499,1
                do
                    modifiedquery = modifiedquery .. tostring(j) .. "th_a int, "
                    if j == 499 then
                        modifiedquery = modifiedquery .. "b_ int, " .. "variance double)" 
                    
                    end
                end
                if i == 15 then
                    proxy.queries:append(-1, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
                else
                    proxy.queries:append(1, string.char(proxy.COM_QUERY) .. modifiedquery , {resultset_is_needed = true});
                end
            end            

            return proxy.PROXY_SEND_QUERY
        

        elseif query == "drop table ciphertext" then
            return drop_handler(query)
    

        -- syntax:
        -- insert into ciphertext values(int, int);
        -- int will be encrypted and stored into ciphertext_biti tables
        elseif string.starts(query, "insert into ciphertext ") then
            return insert_handler(query)    
        
        elseif string.starts(query, "insert into ciphertextdouble ") then
            return insertdouble_handler(query)  

        elseif string.starts(query, "show tablesizes") then
            return size_handler(query)    
        
        elseif string.starts(query, "create udfs") then
            return createudf_handler(query)

        -- table that contains encrypted double 
        elseif query == "create table ciphertextdouble" then
            return createdouble_handler(query)

        elseif query == "drop table ciphertextdouble" then
            return dropdouble_handler(query)

        elseif string.starts(query, "select * from ciphertext where ") then
            return select_handler(query) 

        elseif string.starts(query, "select * from ciphertextdouble where ") then
            return selectdouble_handler(query) 

        elseif string.starts(query, "insert ciphertexts") then
            return insertcts_handler(query) 

        elseif string.starts(query, "insert plaintexts") then
            return insertpts_handler(query) 

        elseif string.starts(query, "generate keys") then 
            mylib.generatekeys()
            proxy.queries:append(21, string.char(proxy.COM_QUERY) .. "select NOW()" , {resultset_is_needed = true});
            return proxy.PROXY_SEND_QUERY
        end
    end
end

function read_query_result(inj)
    originalquery = inj.query:sub(2)

    if ((inj.id <= 4) and (inj.id > -5)) then
        if inj.id == -1 then
            proxy.response.type = proxy.MYSQLD_PACKET_OK
            return proxy.PROXY_SEND_RESULT
        end
        return proxy.PROXY_IGNORE_RESULT
    end

    if (inj.id == 21)then
        proxy.response.type = proxy.MYSQLD_PACKET_OK
        return proxy.PROXY_SEND_RESULT 
    end

    if ((inj.id >= 5) and (inj.id <= 20)) then
        file = io.open("datatobedecrypted" .. (inj.id-5) .. ".txt", "w")
        for rows in inj.resultset.rows do
            for i = 2,503,1 do
                file:write(rows[i] .. "\n")
            end
        end
        file:close()
        decrypted = mylib.HOMdecrypt()
        if (decrypted == nil) then
            return proxy.PROXY_IGNORE_RESULT
        else
            --delete datatobedecrypted files that were created
            for i=0,15,1 do
                os.remove("datatobedecrypted" .. i .. ".txt")
            end

            proxy.response.resultset = {
                fields = {
                    { type = proxy.MYSQL_TYPE_INT24, name = "decrypted", },
                },
                rows = {
                    { decrypted }
                }
            }
            proxy.response.type = proxy.MYSQLD_PACKET_OK
        end
        return proxy.PROXY_SEND_RESULT
    end

    if inj.id <= -5 then
        file = io.open("doubletobedecrypted" .. (-inj.id-5) .. ".txt", "w")
        for rows in inj.resultset.rows do
            for i = 2,503,1 do
                file:write(rows[i] .. "\n")
            end
        end
        file:close()
        decrypted = mylib.HOMdecryptdouble()
        if (decrypted == nil) then
            return proxy.PROXY_IGNORE_RESULT
        else

            --delete doubletobedecrypted files that were created
            for i=0,(2*numbits-1),1 do
                os.remove("doubletobedecrypted" .. i .. ".txt")
            end

            proxy.response.resultset = {
                fields = {
                    { type = proxy.MYSQL_TYPE_DOUBLE, name = "decrypted", },
                },
                rows = {
                    { decrypted }
                }
            }
            proxy.response.type = proxy.MYSQLD_PACKET_OK
        end
        return proxy.PROXY_SEND_RESULT
    end


end


