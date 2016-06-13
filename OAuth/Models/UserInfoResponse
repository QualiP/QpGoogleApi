/*
    Date      :     Monday, June 13, 2016
    Author    :     QualiP (https://github.com/QualiP)
    Objective :     
    Version   :     1.0
*/



using Newtonsoft.Json;


///
/// <summary>
/// Model of a GooglePlus user.
/// </summary>
///
namespace QPGoogleAPI.OAuth.Models
{
    ///
    /// <remarks>
    /// 
    /// Scopes:
    /// https://www.googleapis.com/auth/userinfo.profile
    /// https://www.googleapis.com/auth/userinfo.email
    /// 
    /// GET https://www.googleapis.com/userinfo/v2/me
    /// or
    /// GET https://www.googleapis.com/oauth2/v2/userinfo
    /// </remarks>
    /// 
    public class UserInfoResponse
    {
        [JsonProperty("family_name")]
        public string FamilyName { get; set; }

        [JsonProperty("name")]
        public string Name { get; set; }

        [JsonProperty("picture")]
        public string Picture { get; set; }

        [JsonProperty("locale")]
        public string Locale { get; set; }

        [JsonProperty("email")]
        public string Email { get; set; }

        [JsonProperty("given_name")]
        public string GivenName { get; set; }

        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("verified_email")]
        public string VerifiedEmail { get; set; }
    }
}
