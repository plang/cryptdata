##CryptData##

*CryptData is a Trac plugin that allows you to store data in your Trac wiki in a safe way, by using **RSA public/private encryption**.*

*At the moment, it only supports one-line pieces of text (passwords), but
this might change in the future. Everything has been "namespaced" in
order to make it possible.*

###How does it work?###
When storing data on the server, it is encoded with your RSA 
**public key**. When the user wants to decode the data, he receives the RSA
encrypted data along with your AES encrypted **private key**. He has
first to decode the private key with the **passphrase** he has to remember, and
then use it to decode the RSA encrypted data.

###Is it secure?###
This way of encoding data is secure, yes. Thanks to the RSA
encryption scheme, **no data or decryption key is stored unencrypted 
on the server**. So even if the server is compromised, there's no way 
the attacker can decode the data, unless, of course, if he knows 
the passphrase used to encode the private key. This string 
is not supposed to be stored anywhere, except in the brain of the users.

This system has its limits too. Your data is decrypted on the
client, but is encrypted on the server: that means it is sent once in
plain text through the network. We believe this is something we can live
with, and it helps keeping the plugin easy to code. But for extra security,
consider accessing your trac server through SSL.

###How can I use it?###
You use it like a Trac Macro, like so:

```
[[CPassword(this is my confidential password)]]
```

When saving your trac page, it gets transformed into the following:

```
[[CryptedData(password,A9AREZlKT01kwN4DaDlCrJQdshhzeXG5eGbP7K...)]]
```

This macro gets expanded at runtime into some javascript magic that
prompts the user for the passphrase, decrypts the data, and shows it.

Note: You don't absolutely need to write "CPassword" with the first two letters
capital. "cpassword" will work just fine.

###How can I install it?###
Look at INSTALL file.

###With which Trac versions is it compatible?###
I'm developing with Trac 1.0.1. I'm not sure about other versions.
Feedback is welcome!
