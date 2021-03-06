/*
    Date      :     Monday, June 13, 2016
    Author    :     pdcdeveloper (https://github.com/pdcdeveloper)
    Objective :     
    Version   :     1.0
*/



using Newtonsoft.Json;

namespace QPGoogleAPI.OAuth.Models
{
    ///
    /// <remarks>
    /// 
    /// Scopes:
    /// https://www.googleapis.com/auth/userinfo.profile
    /// https://www.googleapis.com/auth/userinfo.email
    /// 
    /// GET https://www.googleapis.com/plus/v1/people/me
    /// 
    /// </remarks>
    /// 
    public class PlusPersonResponse
    {
        //
        // Always "plus#person"
        //
        [JsonProperty("kind")]
        public string Kind { get; set; }

        [JsonProperty("displayName")]
        public string DisplayName { get; set; }

        [JsonProperty("name")]
        public Name Name { get; set; }

        [JsonProperty("language")]
        public string Language { get; set; }

        [JsonProperty("isPlusUser")]
        public bool IsPlusUser { get; set; }

        [JsonProperty("image")]
        public Image Image { get; set; }

        [JsonProperty("emails")]
        public Emails[] Emails { get; set; }

        [JsonProperty("etag")]
        public string Etag { get; set; }

        [JsonProperty("verified")]
        public bool Verified { get; set; }

        [JsonProperty("id")]
        public string Id { get; set; }

        [JsonProperty("objectType")]
        public string ObjectType { get; set; }
    }




    public class Name
    {
        [JsonProperty("givenName")]
        public string GivenName { get; set; }

        [JsonProperty("familyName")]
        public string FamilyName { get; set; }
    }

    public class Image
    {
        [JsonProperty("url")]
        public string Url { get; set; }

        [JsonProperty("isDefault")]
        public bool IsDefault { get; set; }
    }

    public class Emails
    {
        [JsonProperty("type")]
        public string Type { get; set; }

        [JsonProperty("value")]
        public string Value { get; set; }
    }





}
