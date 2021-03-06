/*
    Date      :     Monday, June 13, 2016
    Author    :     pdcdeveloper (https://github.com/pdcdeveloper)
    Objective :     
    Version   :     1.0
*/


using Newtonsoft.Json;


///
/// <summary>
/// Model for a client secrets json file.
/// </summary>
///
namespace QPGoogleAPI.OAuth.Models
{
    public class InstalledFlowSecrets
    {
        [JsonProperty("installed")]
        public Installed Installed { get; set; }
    }



    public class Installed
    {
        [JsonProperty("client_id")]
        public string ClientId { get; set; }

        [JsonProperty("auth_uri")]
        public string AuthUri { get; set; }

        [JsonProperty("token_uri")]
        public string TokenUri { get; set; }

        [JsonProperty("auth_provider_x509_cert_url")]
        public string AuthProviderX509CertUrl { get; set; }

        [JsonProperty("client_secret")]
        public string ClientSecret { get; set; }

        //
        // Do not use localhost for the installed flow, which is typically the ElementAt(1)
        //
        [JsonProperty("redirect_uris")]
        public string[] RedirectUris { get; set; }
    }
}
