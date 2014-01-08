// Copyright (C) 2013 Philippe Lang <philippe.lang@cromagnon.ch>
// All rights reserved.
//
// This software is licensed as described in the file COPYING, which
// you should have received as part of this distribution.
//
// Author: Philippe Lang <philippe.lang@cromagnon.ch>

$(function() {

    // Set default theme for Vex
    vex.defaultOptions.className = 'vex-theme-default';

    // Show dialog on click
    $(".cryptdata-password > a").click(function() {

        // Saving the link the user has clicked onto
        $link = $(this);

        // Dialog
        vex.dialog.open({
            message: "",
            input: "<input name='password' type='password' placeholder='RSA passphrase' required />",
            buttons: [
                $.extend({}, vex.dialog.buttons.YES, {
                    text: 'OK'
                })
            ],
            callback: function(data) {
                if (data === false) {
                    //alert('Cancelled');
                }
                else {
                    try {
                        // Get input data
                        private_key_encoded = $("meta[name=private_key_encoded]").attr("content");
                        password_encrypted_base64 = $link.siblings(".encrypted_password").html();

                        // Parse the private key
                        params = certParser(private_key_encoded);
                        
                        // Aes-cbc decoding
                        aes = new pidCrypt.AES.CBC();
                        salt = params.salt;
                        k_and_iv = aes.createKeyAndIv({password:data.password, salt:salt, bits:params.bits});
                        aes.initByValues(params.b64, k_and_iv.key, params.iv.toLowerCase(), {UTF8:false, A0_PAD:false, nBits:params.bits});
                        rsapem_decrypted = aes.decrypt();
    
                        // ASN1 Parsing
                        decryptedBytes = pidCryptUtil.toByteArray(rsapem_decrypted);
                        asn = pidCrypt.ASN1.decode(decryptedBytes);
                        asnTree = asn.toHexTree();
    
                        // RSA decoding
                        rsa = new pidCrypt.RSA();
                        // Set the private key based on the result of the ASN1 parsing
                        rsa.setPrivateKeyFromASN(asnTree);
                        // Prepare text to decode
                        ciphertext = pidCryptUtil.decodeBase64(pidCryptUtil.stripLineFeeds(password_encrypted_base64));
                        // Decode
                        plain = rsa.decryptRaw(pidCryptUtil.convertToHex(ciphertext));

                        // Deleting variables for safety
                        delete private_key_encoded;
                        delete password_encrypted_base64;
                        delete params;
                        delete aes;
                        delete salt;
                        delete k_and_iv;
                        delete rsapem_decrypted;
                        delete decryptedBytes;
                        delete asn;
                        delete asnTree;
                        delete rsa;
                        delete ciphertext;

                        // Displaying the decoded password
                        vex.dialog.open({
                            message: "",
                            input: "<input id='plain' name='plain' type='text' /><div style='font-size: 12px'>Press CTRL/CMD - C and Close</div>",
                            buttons: [
                                $.extend({}, vex.dialog.buttons.YES, {
                                    text: 'Close'
                                })
                            ],
                            afterOpen: function($vexContent) {
                                $('#plain').val(plain).select();
                            },
                            callback: function(data) {
                            }
                        });

                        // Deleting the variable for safety
                        delete plain;
                    }
                    catch (err)
                    {
                        // Something went wrong, most likely a wrong password entered by the user
                        vex.dialog.alert('Sorry, unable to decrypt the password.')
                    }
                }
            }
        });
    });
});
