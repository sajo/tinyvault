# Tiny vault

PT-BR

Este é um gerenciador de senhas simples, ele foi construido para ser executado no navegador sem bibliotecas externas e com opção para uso via linha de comando com nodejs.

EN

This is a simple password manager, built to run in the browser without external libraries and can be used with the Nodejs command line interface


BROWSER - HTML TAG 

```HTML
<script type="application/javascript" src="vault.js">
````

Init
```Javascript
var vt  = new Vault();
vt.iterations = 100000; // 1000000
vt.pbkdf2Sizebits = 256;
vt.mode = "AES-CBC"; // CBC OR GCM
passVault.hash = "SHA-256"; // 256 or 512
````


```Javascript
var data = await vt.generate("P4ssw0rd");
await vt.addPass("P4ssw0rd",vt.data,"google","MyNickName",'1@Pass');
await vt.viewPass("simpleP4ssw0rd",vt.data);
await vt.dellPass("6b010f",vt.data);
```

Module 

```
npm install @sajo/tinyvault --registry=https://registry.npmjs.org
```
NODE CLI
```
npm install -g @sajo/tinyvault --registry=https://registry.npmjs.org
```



```sh
tinyvault -mode=generate -password=P4ssw0rd
tinyvault -mode=addpass -password=P4ssw0rd -extra=google -user=MyNickName -newpass=1@Pass
tinyvault -mode=viewpass -password=P4ssw0rd
tinyvault -mode=dellpass -idpass=<idAvailable@vault>
```


