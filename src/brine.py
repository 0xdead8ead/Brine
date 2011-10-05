#!/usr/bin/python2.7

import cPickle as pickle
from CryptoWrapper import CryptoWrapper

class Brine():
    
    def __init__(self):
        self.picklePad = 'pickle::'
    
    __verifyPickle__(encryptedPickle, verficationKey):
        crypto = CryptoWrapper()
        if crypto.rsaVerify(pubKey, data, signature)
    
    def dumps(self, obj, signingPrivateKey, receipientPublicKey, pickler=pickle):
        '''pickle and encrypt a python object - SHIT NEEDS WORK, too many arguments'''
        cryptoWrapper = CryptoWrapper();
        encryptedPickle, aesKey = cryptoWrapper.aesEncrypt(self.picklePad + pickler.dumps(obj))
#        print 'Encrypted Pickle: %s' % encryptedPickle
#        print 'AES Key: \n\n' % aesKey
        pickleSignature = cryptoWrapper.rsaSign(signingPrivateKey, encryptedPickle)
        encryptedKey = cryptoWrapper.rsaPublicEncrypt(receipientPublicKey, aesKey)
        return encryptedPickle, encryptedKey, pickleSignature
    

    def loads(self, encryptedPickle, encryptedKey, pickleSignature, receipientPrivateKey, verificationKey, pickler=pickle):
        '''SHIT NEEDS WORK'''
        cryptoWrapper = CryptoWrapper()
        
        data = self.decrypt(data)
        # simple integrity check to verify that we got meaningful data
        assert data.startswith(self.picklePad), "unexpected header"
        return pickler.loads(data[len(self.picklePad):])
   
if __name__ == '__main__':
    
    crypto = CryptoWrapper()
    signingKey, verificationKey = crypto.generateRSAKeys(2048)
    receipientPrivateKey, receipientPublicKey = crypto.generateRSAKeys(2048)
    
    brine = Brine()
    
    
    dict = {'cat': 'hackers', 'bill': 45}
    encryptedPickle, encryptedKey, pickleSignature = brine.dumps(dict, signingKey, receipientPublicKey)
    print 'Encrypted Pickle: %s\n' % encryptedPickle
    print 'Encrypted Pickle Key: %s\n' % encryptedKey
    print 'Pickle Signature: %s\n' % pickleSignature