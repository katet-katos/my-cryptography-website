import uuid
import hashlib
def SHA256(new_pass):
    def hash_password(password):
        # uuid используется для генерации случайного числа
        salt = uuid.uuid4().hex
        return hashlib.sha256(salt.encode() + password.encode()).hexdigest() + ':' + salt
            
    hashed_password = hash_password(new_pass)
    return hashed_password


def MD5(new_pass):
    def hash_password(password):
        # uuid используется для генерации случайного числа
        salt = uuid.uuid4().hex
        return hashlib.md5(salt.encode() + password.encode()).hexdigest() + ':' + salt

    hashed_password = hash_password(new_pass)
    return hashed_password


def SHA1(new_pass):
    def hash_password(password):
        # uuid используется для генерации случайного числа
        salt = uuid.uuid4().hex
        return hashlib.sha1(salt.encode() + password.encode()).hexdigest() + ':' + salt
      
    hashed_password = hash_password(new_pass)
    return hashed_password



def SHA224(new_pass):
    def hash_password(password):
        # uuid используется для генерации случайного числа
        salt = uuid.uuid4().hex
        return hashlib.sha224(salt.encode() + password.encode()).hexdigest() + ':' + salt
           
    hashed_password = hash_password(new_pass)
    return hashed_password
    


def SHA384(new_pass):
    def hash_password(password):
        # uuid используется для генерации случайного числа
        salt = uuid.uuid4().hex
        return hashlib.sha384(salt.encode() + password.encode()).hexdigest() + ':' + salt

    hashed_password = hash_password(new_pass)
    return hashed_password
