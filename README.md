# PKCS12ProtectedConfigurationProvider

A modified version of the PKCS12ProtectedConfigurationProvider that can specify a store location to search

# Encrypting a config

Use the Visual Studio Command Promot for these commands.

## Generate a cert

1. Generate a certificate using `makecert`
  - `makecert -r -pe -n CN=mycert -sky exchange mycert.cer -sv mycert.pvk`
2. Generate a PFX file to store private/public key pair
  - `pvk2pfx -pvk mycert.pvk -spc mycert.cer -pfx mycert.pfx -pi <password>`
3. Install the PFX into your `Current User\Personal` store
4. If using IIS:
  - Also install it into your `Local Machine\Personal` certificate store
  - Grant permissions to the private key (Right-click cert, All Tasks -> Manage Private Keys...) to IIS_IUSRS
5. Copy the thumbprint of your certificate

## Modify web.config

1. Download the provider DLL to your machine (see [Releases](https://github.com/kamranayub/PKCS12ProtectedConfigurationProvider/releases/tag/v1.0.1))
2. Install the DLL to the GAC
  - `gacutil -i PKCS12ProtectedConfigurationProvider.dll`
3. Reference the DLL in your project (Add Reference...) and copy to application directory
4. Add a new section to your web.config:

  ```xml
    <configProtectedData>
        <providers>
            <add name="CustomProvider"
                 thumbprint="cert thumbprint"
                 storeLocation="LocalMachine"
                 type="Pkcs12ProtectedConfigurationProvider.Pkcs12ProtectedConfigurationProvider, PKCS12ProtectedConfigurationProvider, Version=1.0.1.0, Culture=neutral, PublicKeyToken=455a6e7bdbdc9023" />
        </providers>
    </configProtectedData>
  ```

5. Encrypt sections of your config as needed:
  - `aspnet_regiis -pef appSecrets . -prov CustomProvider`
  - `aspnet_regiis -pef connectionStrings . -prov CustomProvider`
  
## Azure

Make sure you upload the `.pfx` file to Azure through the portal.

1. Navigate to your Web App
2. Navigate to the Settings blade
3. Scroll down to "Custom Domains and SSL"
4. Click the "Upload Certificate" button in the toolbar (remember your password!)

**YOU CANNOT ENCRYPT THE `<appSettings>` SECTION IN AZURE WEB APPS!** See [this SO question](http://stackoverflow.com/questions/15067759/why-cant-i-encrypt-web-config-appsettings-using-a-custom-configprotectionprovid).

Other sections are just fine but for whatever reason, IIS just **requires** you to GAC the config provider for it to work. In Azure web apps, we cannot GAC. So what can we do? We can use our **own** config section!

[Here's an implementation example](https://gist.github.com/kamranayub/eb6518356ac2b2f1a72a) of an `ISecretsProvider` contract and a `ConfigSecretsProvider` example implementation.

The `ConfigSecretsProvider` will use environment variables defined in Azure *first* then fallback to the config. This mirrors how app settings work in Azure.

To encrypt the `<appSecrets>` section, just run the the command (in the same directory as the web.config and using the Visual Studio Command Prompt):

```
aspnet_regiis -pef appSecrets . -prov CustomProvider
```

And to decrypt:

```
aspnet_regiis -pdf appSecrets .
```

### If you use LocalMachine store locally

If you run your app under `ApplicationPoolIdentity` or any other identity other than yourself, you are probably using `storeLocation="LocalMachine"` for the PKCS provider. In Azure, this won't work. For Azure, certificates that are uploaded are stored under `Cert:\CurrentUser\My` **not** `LocalMachine`.

The easiest way to address this is by [changing the identity](http://www.iis.net/learn/manage/configuring-security/application-pool-identities) your app pool runs under (or use IIS Express) to your account.
