/*
    Date      :     Monday, June 13, 2016
    Author    :     QualiP (https://github.com/QualiP)
    Objective :     
    Version   :     1.0
*/


using Newtonsoft.Json;


///
/// <summary>
/// Model for the token response from Google after a successful authorization request.
/// </summary>
///
namespace QPGoogleAPI.OAuth.Models
{
    public class OAuthTokenResponse
    {
        [JsonProperty("access_token")]
        public string AccessToken { get; set; }

        [JsonProperty("token_type")]
        public string TokenType { get; set; }

        [JsonProperty("expires_in")]
        public int ExpiresIn { get; set; }

        [JsonProperty("refresh_token")]
        public string RefreshToken { get; set; }
    }
}
