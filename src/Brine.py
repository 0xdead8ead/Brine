#!/usr/bin/env python

'''

Brine Secure Pickling Module - By Chase Schultz

Currently Supports: AES-256 Encrypted Pickles, RSA Public Key Encrypted Symmetric, RSA Signed Pickles

Dependencies: pyCrypto - https://github.com/dlitz/pycrypto


Brine Secured/Authenticated Pickles - based cPickle and pyCrypto
    Copyright (C) 2011  Chase Schultz - chaschul@uat.edu

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.


'''

__author__ = 'Chase Schultz'
__version__ = '0.1'

import os
import cPickle as pickle
from CryptoWrapper import CryptoWrapper


class Brine():
    
    def __init__(self):
        self.picklePad = 'pickle::'
    
    def __verifyPickle__(self, encryptedPickle, verficationKey, signature):
        '''Veryify Pickle Authenticity with RSA Signature - Return True if good Signature'''
        crypto = CryptoWrapper()
        if crypto.rsaVerify(verificationKey, encryptedPickle, signature) is False:
            raise Exception('Could not Verify Pickle')
            os._exit(1)
        else:
            return True
    
    def __decryptPickle__(self,encryptedPickle, encryptedKey):
        
        pass
    
    def dumps(self, obj, signingPrivateKey, receipientPublicKey, pickler=pickle):
        '''Pickle and Encrypt a Python Object with AES / Encrypt AES Key with Receipient Public RSA Key / Signs Pickle with Sender Private Key'''
        cryptoWrapper = CryptoWrapper();
        encryptedPickle, aesKey = cryptoWrapper.aesEncrypt(self.picklePad + pickler.dumps(obj))
        pickleSignature = cryptoWrapper.rsaSign(signingPrivateKey, encryptedPickle)
        encryptedKey = cryptoWrapper.rsaPublicEncrypt(receipientPublicKey, aesKey)
        return encryptedPickle, encryptedKey, pickleSignature
    

    def loads(self, encryptedPickle, encryptedKey, pickleSignature, receipientPrivateKey, verificationKey, pickler=pickle):
        '''Checks Pickle Signature / Decrypts AES Key and Pickle and Loads Object'''
        cryptoWrapper = CryptoWrapper()
        try:
            self.__verifyPickle__(encryptedPickle, verificationKey, pickleSignature)
        except:
            print 'Invalid Pickle - Not Decrypting'
            raise Exception('Pickle Fails Signature Verification')
        aesKey = cryptoWrapper.rsaPrivateDecrypt(receipientPrivateKey, encryptedKey)
        pickle = cryptoWrapper.aesDecrypt(aesKey, encryptedPickle)
        # simple integrity check to verify that we got meaningful data
        assert pickle.startswith(self.picklePad), "unexpected header"
        return pickler.loads(pickle[len(self.picklePad):])
   
if __name__ == '__main__':
    '''Usage Examples'''
    
    '''Instatiation of Crypto Wrapper - Generate Signing Key Pair and RSA Key Pair'''
    crypto = CryptoWrapper()
    signingKey, verificationKey = crypto.generateRSAKeys(2048)
    receipientPrivateKey, receipientPublicKey = crypto.generateRSAKeys(2048)
    
    
    '''Instatiation of Brine Module - Dumps Python object into Encyrpted Pickle'''
    dict = {'object': 'to be', 'pickled': 'test case'}
    brine = Brine()
    encryptedPickle, encryptedKey, pickleSignature = brine.dumps(dict, signingKey, receipientPublicKey)
        
    '''Unencrypt Pickle Object and Return object'''
    unpickledObject = brine.loads(encryptedPickle, encryptedKey, pickleSignature, receipientPrivateKey, verificationKey)
    print unpickledObject
    
    