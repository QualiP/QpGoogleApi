/*
    Date      :     Monday, June 13, 2016
    Author    :     pdcdeveloper (https://github.com/pdcdeveloper)
    Objective :     Implements the complete OAuth installed flow for any of Google's services, automatically manages
                    use of a user's refresh token and revocation requests to Google.
    Version   :     1.0
*/



using Newtonsoft.Json;
using QPGoogleAPI.OAuth.Models;
using QPLib.Base;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using Windows.Security.Authentication.Web;
using Windows.Security.Credentials;
using Windows.Storage;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Media.Imaging;
using Windows.Web.Http;
using Windows.Web.Http.Headers;

namespace QPGoogleAPI.OAuth.Flows
{
    ///
    /// <summary>
    /// Implements the complete OAuth installed flow for any of Google's services, automatically manages
    /// use of a user's refresh token and revocation requests to Google.
    /// </summary>
    /// 

    ///
    /// <remarks>
    ///
    /// Stores multiple users, with the first user within the vault as the default user.
    ///
    /// Storing tokens (securely):
    /// <see cref="https://msdn.microsoft.com/en-us/library/windows/apps/windows.security.credentials.passwordvault.aspx"/>
    /// <see cref="https://msdn.microsoft.com/en-us/library/windows/apps/hh701231.aspx"/>
    /// <see cref="https://stackoverflow.com/questions/9052482/best-practice-for-saving-sensitive-data-in-windows-8"/>
    /// 
    /// General information on Google's OAuth implementation (DO NOT use the Windows 8.1 example code):
    /// <see cref="https://developers.google.com/youtube/v3/guides/auth/installed-apps"/>
    /// 
    /// The classes that support OAuth2 for WinRT:
    /// <see cref="https://msdn.microsoft.com/windows/uwp/security/web-authentication-broker"/>
    /// <see cref="https://msdn.microsoft.com/en-us/library/windows/apps/windows.security.authentication.web.aspx"/>
    /// <see cref="https://msdn.microsoft.com/en-us/library/windows/apps/xaml/windows.security.authentication.web.webauthenticationbroker.aspx"/>
    /// <see cref="https://msdn.microsoft.com/en-us/library/windows/apps/xaml/windows.security.authentication.web.webauthenticationresult.aspx"/>
    /// 
    /// DO NOT USE THE EXAMPLES FROM THIS DOCUMENT!!!
    /// <donotsee cref="https://developers.google.com/api-client-library/dotnet/guide/aaa_oauth#user-credentials"/>
    /// 
    /// 
    /// 
    /// Extremely helpful post about... POST - authorized token exchange:
    /// <see cref="https://stackoverflow.com/questions/15176538/net-httpclient-how-to-post-string-value"/>
    /// 
    /// 
    /// 
    /// 
    /// How PasswordCredential is stored:
    ///     PasswordCredential.UserName = "PlusPersonResponse.DisplayName,PlusPersonResponse.Id,PlusPersonResponse.ProfileImageUrl"
    ///     PasswordCredential.Resource = "APP_NAME,TokenResponse.TokenType"
    ///     PasswordCredential.Password = "TokenResponse.AccessToken,TokenResponse.RefreshToken,TokenResponse.ExpiresIn.ToString(),DateTime.UtcNow.ToString()"
    /// 
    /// 
    /// This entire class is centered around the PasswordCredential, which makes the overall design very hack-ish.
    /// 
    /// 
    /// </remarks>
    ///

    ///
    /// <updates>
    /// 
    /// Update 2016-06-01:
    ///     Added retry attempts within TryExchangeForAccessTokenAsync().
    ///
    /// Update 2016-06-13:
    ///     Currently, only asks for YouTube, Profile and Email scopes.
    /// 
    /// </updates>
    ///
    public class OAuthInstalledFlow : NotifyPropertyChangedBase
    {

        static readonly string APP_NAME = Application.Current.ToString();





        //
        // Installed secrets path
        //
        const string INSTALLED_FLOW_SECRETS_PATH = @"ms-appx:///YOUR_CLIENT_SECRETS.json";








        //
        // Scopes
        //
        const string YOUTUBE_SCOPE = @"https://www.googleapis.com/auth/youtube.force-ssl";


        // UserInfoResponse:
        //  GET https://www.googleapis.com/userinfo/v2/me
        //      or
        //  GET https://www.googleapis.com/oauth2/v2/userinfo
        //
        // PlusPersonResponse:
        //  GET https://www.googleapis.com/plus/v1/people/me
        //
        // Currently using UserInfoResponse rest api call.
        //
        const string PROFILE_SCOPE = @"https://www.googleapis.com/auth/userinfo.profile";
        const string EMAIL_SCOPE = @"https://www.googleapis.com/auth/userinfo.email";   // Uses the same api call as PROFILE_SCOPE

        //
        // Space delimited
        //
        const string AUTHENTICATION_SCOPES 
            = YOUTUBE_SCOPE + @" "
            + PROFILE_SCOPE + @" "
            + EMAIL_SCOPE;









        #region rest api calls
        //
        // Revocation -- requires the token parameter
        //
        const string REVOCATION_API_URL = @"https://accounts.google.com/o/oauth2/revoke?token=";

        //
        // User info, such as name and profile image -- requires a bearer token in the auth header of the GET request.
        // Use with either PROFILE_SCOPE or EMAIL_SCOPE.
        //
        const string USER_INFO_API_URL = @"https://www.googleapis.com/oauth2/v2/userinfo";
        #endregion

































        //
        // Easy for the view and gets rid of repetitive checks
        //
        static BitmapImage _profileImage = null;
        public BitmapImage ProfileImage
        {
            get
            {
                if (AuthorizedUser != null)
                {
                    _profileImage.DecodePixelHeight = 50;
                    _profileImage.DecodePixelWidth = 50;
                    return _profileImage;
                }

                return null;
            }
            set
            {
                _profileImage = value;
                OnPropertyChanged();
            }
        }



















        //
        // This is the current user.
        // Use the token helpers instead of accessing this property directly.
        //
        static AuthorizedUser _authorizedUser = null;
        [DisplayAttribute(Name = "AuthorizedUser")]
        public AuthorizedUser AuthorizedUser
        {
            get
            {
                if (_authorizedUser != null)
                    return _authorizedUser;

                //
                // Call this setter to invoke a property change.
                // This is optional, otherwise you would explicitly return null.
                // 
                //
                //AuthorizedUser = TryGetDefaultAuthorizedUser();   // loop detected
                //return _authorizedUser;

                return null;
            }
            set
            {
                _authorizedUser = value;


                //
                // Property changed event for profile image
                //
                if (value != null && !string.IsNullOrEmpty(value.ProfileImageUrl))
                    ProfileImage = new BitmapImage(new Uri(value.ProfileImageUrl, UriKind.Absolute));
                else
                    ProfileImage = null;


                OnPropertyChanged();
                OnSingletonPropertyChanged();
            }
        }












        //
        // To do:  an actual try-catch block
        //
        AuthorizedUser TryGetDefaultAuthorizedUser()
        {
            //if (_authorizedUser != null)
            //    return _authorizedUser;


            //
            // Try to get the default user from the vault
            //
            PasswordVault vault = new PasswordVault();
            PasswordCredential cred = null;
            IReadOnlyList<PasswordCredential> credentials = vault.RetrieveAll();
            if (credentials != null && credentials.Count > 0)
            {
                cred = credentials.First();
            }



            //
            // Break
            //
            if (cred == null)
                return null;


            //
            // Prep a new user
            //
            AuthorizedUser user = new AuthorizedUser();

            //
            // Password
            //
            cred.RetrievePassword();
            if (!string.IsNullOrEmpty(cred.Password))
            {
                user.AccessToken = cred.Password.Split(',').ElementAt(0);
                user.RefreshToken = cred.Password.Split(',').ElementAt(1);
                user.ExpiresIn = int.Parse(cred.Password.Split(',').ElementAt(2));
                user.DateAcquiredUtc = DateTime.Parse(cred.Password.Split(',').ElementAt(3));
            }



            //
            // Resource
            //
            if (!string.IsNullOrEmpty(cred.Resource) && cred.Resource.Split(',').ElementAt(0).Contains(APP_NAME))
            {
                user.TokenType = cred.Resource.Split(',').ElementAt(1);
            }


            //
            // UserName
            //
            if (!string.IsNullOrEmpty(cred.UserName))
            {
                user.DisplayName = cred.UserName.Split(',').ElementAt(0);
                user.Id = cred.UserName.Split(',').ElementAt(1);
                user.ProfileImageUrl = cred.UserName.Split(',').ElementAt(2);
            }


            //
            //
            //
            return user;

        }




























































































        #region public functionality


        public async Task LoginAsync()
        {
            //
            // Ask the user to authenticate by bringing up the broker
            //
            string authorizationToken = await this.TryGetAuthorizationTokenAsync();
            if (string.IsNullOrEmpty(authorizationToken))
                return;

            //
            // Exchange authorization token for access and refresh tokens
            //
            PasswordCredential credential = await this.TryExchangeForAccessTokenAsync(authorizationToken);


            //
            // Break
            //
            if (credential == null)
                return;






            //
            // Check if the user already exists before storing in the vault.
            // Always compare by id, never by name.
            //
            PasswordVault vault = new PasswordVault();
            IReadOnlyList<PasswordCredential> credentials = null;
            if (!string.IsNullOrEmpty(credential.UserName))
            {
                string id = credential.UserName.Split(',').ElementAt(1);

                credentials = vault.RetrieveAll();
                if (credentials != null && credentials.Count > 0)
                    foreach (var cred in credentials)
                    {
                        if (string.IsNullOrEmpty(cred.UserName))
                            continue;

                        string credId = cred.UserName.Split(',').ElementAt(1);
                        if (credId == id)
                        {
                            cred.RetrievePassword();
                            string accessToken = cred.Password.Split(',').ElementAt(0);

                            //
                            // Revoke, remove from the vault, and from the view, if applicable
                            //
                            await this.RevokeTokensAsync(accessToken);
                            break;
                        }
                    }
            }






            //
            // Store the credential
            //
            vault.Add(credential);






            //
            // Fill out a new authorized user
            //
            AuthorizedUser user = new AuthorizedUser();

            //
            // Password
            //
            user.AccessToken = credential.Password.Split(',').ElementAt(0);
            user.RefreshToken = credential.Password.Split(',').ElementAt(1);
            user.ExpiresIn = int.Parse(credential.Password.Split(',').ElementAt(2));
            user.DateAcquiredUtc = DateTime.Parse(credential.Password.Split(',').ElementAt(3));

            //
            // Resource
            //
            user.TokenType = credential.Resource.Split(',').ElementAt(1);

            //
            // UserName
            //
            if (!string.IsNullOrEmpty(credential.UserName))
            {
                user.DisplayName = credential.UserName.Split(',').ElementAt(0);
                user.Id = credential.UserName.Split(',').ElementAt(1);
                user.ProfileImageUrl = credential.UserName.Split(',').ElementAt(2);
            }




            //
            // Update the view
            //
            AuthorizedUser = user;
        }
































        public async Task LogoutAsync(PasswordCredential credential)
        {
            if (credential == null)
                return;

            credential.RetrievePassword();
            if (string.IsNullOrEmpty(credential.Password))
                return;

            string accessToken = credential.Password.Split(',').ElementAt(0);

            //
            // Revoke the token, remove from the vault and from the view, if applicable
            //
            await this.RevokeTokensAsync(accessToken);
        }



        //
        // Implicitly log out the current authorized user
        //
        public async Task LogoutAsync()
        {
            if (_authorizedUser == null)
                return;

            //
            // Find the current authorized user
            //
            PasswordVault vault = new PasswordVault();
            IReadOnlyList<PasswordCredential> credentials = vault.RetrieveAll();
            if (credentials?.Count > 0)
            {
                //
                // Try revoking by id
                //
                if (!string.IsNullOrEmpty(_authorizedUser.Id))
                    foreach (var cred in credentials)
                    {
                        if (string.IsNullOrEmpty(cred.UserName))
                            continue;

                        string credId = cred.UserName.Split(',').ElementAt(1);
                        if (credId == _authorizedUser.Id)
                        {
                            await this.RevokeTokensAsync(_authorizedUser.RefreshToken);
                            return;
                        }
                    }


                //
                // Try revoking by refresh token
                //
                if (!string.IsNullOrEmpty(_authorizedUser.RefreshToken))
                    foreach (var cred in credentials)
                    {
                        cred.RetrievePassword();

                        string credRefresh = cred.Password.Split(',').ElementAt(1);
                        if (credRefresh == _authorizedUser.RefreshToken)
                        {
                            await this.RevokeTokensAsync(_authorizedUser.RefreshToken);
                            return;
                        }
                    }
            }
        }













































































































        //
        // The parameter that is most likely to be passed in is
        // this.AuthorizedUser.
        //
        public async Task UseRefreshToken(AuthorizedUser user)
        {
            if (user == null)
                return;

            if (string.IsNullOrEmpty(user.RefreshToken)
                || user.DateAcquiredUtc == null)
                return;


            //
            //
            //
            InstalledFlowSecrets secrets = await GetInstalledFlowSecretsAsync();
            PasswordVault vault = new PasswordVault();
            IReadOnlyList<PasswordCredential> credentials = null;
            OAuthTokenResponse oauthTokens = null;


            //
            //
            //
            using (HttpClient client = new HttpClient())
            {
                Uri tokenUri = new Uri(secrets.Installed.TokenUri, UriKind.Absolute);

                //
                // Create POST content
                //
                Dictionary<string, string> content = new Dictionary<string, string>();
                content.Add("client_id", secrets.Installed.ClientId);
                content.Add("client_secret", secrets.Installed.ClientSecret);
                content.Add("refresh_token", user.RefreshToken);
                content.Add("grant_type", "refresh_token");
                // state parameter is not allowed

                //
                // Url encode the content
                //
                HttpFormUrlEncodedContent body = new HttpFormUrlEncodedContent(content);

                //
                // Send a POST request with the content body
                //
                HttpResponseMessage refreshResponse = await client.PostAsync(tokenUri, body);

                //
                // Break -- the token was probably revoked from outside this application
                //
                if (refreshResponse == null || !refreshResponse.IsSuccessStatusCode)
                {
                    //
                    // Revoke the user from the service, then remove from the vault and from the view, if applicable.
                    // Although you will get a bad request if the refresh token has already been revoked, the credential
                    // will still be scrubbed away.
                    //
                    await this.RevokeTokensAsync(user.RefreshToken);
                    return;
                }


                //
                // Deserialize the JSON content
                //
                string jsonRefreshText = await refreshResponse.Content.ReadAsStringAsync();
                oauthTokens = JsonConvert.DeserializeObject<OAuthTokenResponse>(jsonRefreshText);
            }






            //
            // Refresh the credential within the vault with a new PasswordCredential
            //
            PasswordCredential credential = new PasswordCredential();
            DateTime dateAcquiredUtc = DateTime.UtcNow;

            //
            // Password
            //
            credential.Password
                = oauthTokens.AccessToken
                + ',' + user.RefreshToken
                + ',' + oauthTokens.ExpiresIn.ToString()
                + ',' + dateAcquiredUtc.ToString();

            //
            // Resource
            //
            credential.Resource
                = APP_NAME
                + ',' + oauthTokens.TokenType;

            //
            // UserName
            //
            if (!string.IsNullOrEmpty(user.DisplayName))
            {
                credential.UserName
                    = user.DisplayName
                    + ',' + user.Id
                    + ',' + user.ProfileImageUrl;
            }




            //
            // Find the credential in the vault and remove it before adding its replacement
            //
            credentials = vault.RetrieveAll();
            if (credentials != null && credentials.Count > 0)
                foreach (var cred in credentials)
                {
                    cred.RetrievePassword();
                    if (!string.IsNullOrEmpty(cred.Password))
                        if (cred.Password.Contains(user.RefreshToken))
                        {
//#if DEBUG
//                            Debug.WriteLine(Environment.NewLine);
//                            Debug.WriteLine("Credential being updated:");
//                            Debug.WriteLine(cred.Password.Split(',').ElementAt(0));
//                            Debug.WriteLine(cred.Password.Split(',').ElementAt(1));
//                            Debug.WriteLine(cred.Password.Split(',').ElementAt(2));
//                            Debug.WriteLine(cred.Password.Split(',').ElementAt(3));
//                            Debug.WriteLine(Environment.NewLine);
//#endif
                            vault.Remove(cred);
                            break;
                        }
                }



            //
            //
            //
            vault.Add(credential);



//#if DEBUG
//            credentials = vault.RetrieveAll();
//            if (credentials != null && credentials.Count > 0)
//                foreach (var cred in credentials)
//                {
//                    cred.RetrievePassword();
//                    if (!string.IsNullOrEmpty(cred.Password))
//                        if (cred.Password.Contains(user.RefreshToken))
//                        {
//                            Debug.WriteLine(Environment.NewLine);
//                            Debug.WriteLine("Checking if the credential has been updated:");
//                            Debug.WriteLine(cred.Password.Split(',').ElementAt(0));
//                            Debug.WriteLine(cred.Password.Split(',').ElementAt(1));
//                            Debug.WriteLine(cred.Password.Split(',').ElementAt(2));
//                            Debug.WriteLine(cred.Password.Split(',').ElementAt(3));
//                            Debug.WriteLine(Environment.NewLine);
//                            break;
//                        }
//                }
//#endif


            //
            // Refresh _authorizedUser, if applicable
            //
            if (_authorizedUser != null && _authorizedUser.RefreshToken == user.RefreshToken)
            {
                //
                // The view gets updated implicitly -- AuthorizedUser implements NotifyPropertyChangedBase for each of its properties
                //
                _authorizedUser.AccessToken = oauthTokens.AccessToken;
                _authorizedUser.ExpiresIn = oauthTokens.ExpiresIn;
                _authorizedUser.TokenType = oauthTokens.TokenType;
                _authorizedUser.DateAcquiredUtc = dateAcquiredUtc;
            }
        }














        //
        // Alternate version
        //
        public async Task UseRefreshToken(PasswordCredential credential)
        {
            //
            // To do:
            // Build a AuthorizedUser object from the Password credential,
            // then call the overload.
            //
        }

































































        //
        // Change the user by passing in a credential from the vault.
        // You can also use this method to set the default user when the application launches.
        //
        public void ChangeUser(PasswordCredential credential)
        {
            if (credential == null)
                return;

            credential.RetrievePassword();
            if (string.IsNullOrEmpty(credential.Password))
                return;


            //
            // Check if the credential is in the vault
            //
            PasswordVault vault = new PasswordVault();
            IReadOnlyList<PasswordCredential> credentials = vault.RetrieveAll();
            if (credentials != null && credentials.Count > 0)
                foreach (var cred in credentials)
                {
                    string refreshToken = credential.Password.Split(',').ElementAt(1);
                    cred.RetrievePassword();
                    if (cred.Password.Contains(refreshToken))
                        break;
                    else if (cred == credentials.Last())
                        return;
                    else
                        continue;
                }
            else
                return;


            //
            // Build an AuthorizedUser
            //
            AuthorizedUser user = new AuthorizedUser();



            //
            // Password
            //
            user.AccessToken = credential.Password.Split(',').ElementAt(0);
            user.RefreshToken = credential.Password.Split(',').ElementAt(1);
            user.ExpiresIn = int.Parse(credential.Password.Split(',').ElementAt(2));
            user.DateAcquiredUtc = DateTime.Parse(credential.Password.Split(',').ElementAt(3));

            //
            // Resource
            //
            user.TokenType = credential.Resource.Split(',').ElementAt(1);

            //
            // UserName
            //
            if (!string.IsNullOrEmpty(credential.UserName))
            {
                user.DisplayName = credential.UserName.Split(',').ElementAt(0);
                user.Id = credential.UserName.Split(',').ElementAt(1);
                user.ProfileImageUrl = credential.UserName.Split(',').ElementAt(2);
            }

            //
            // Change the user to propagate property changes
            //
            AuthorizedUser = user;
        }




































        //
        // Uninstall scenario or if user wants to clear all previous credentials
        // from both the service and the vault.
        //
        public async Task RevokeAllTokensAndClearVaultAsync()
        {
            PasswordVault vault = new PasswordVault();
            IReadOnlyList<PasswordCredential> credentials = vault.RetrieveAll();


            string[] tokens;


            if (credentials != null && credentials.Count > 0)
            {
                tokens = new string[credentials.Count];

                for (int i = 0; i < credentials.Count; i++)
                {
                    credentials[i].RetrievePassword();
                    tokens[i] = credentials[i].Password.Split(',').ElementAt(0);
                }
            }
            else
                //
                // Break -- there is nothing to revoke
                //
                return;

            //
            // Break -- something went wrong when building the array
            //
            if (tokens == null)
                return;

            if (tokens.Length < 1)
                return;


            //
            // Revoke, then remove each token from the vault
            //
            await this.RevokeTokensAsync(tokens);
        }

        #endregion



















































        #region helpers
        public virtual string AccessTokenHelper()
        {
            if (AuthorizedUser != null)
                return AuthorizedUser.AccessToken;
            return null;
        }



        public virtual async Task RefreshTokenHelper()
        {
            if (AuthorizedUser != null)
                if (AuthorizedUser.IsAccessTokenExpired)
                    await UseRefreshToken(AuthorizedUser);
        }
        #endregion















































































































































        #region developer console
        static InstalledFlowSecrets _developerSecrets = null;
        async Task<InstalledFlowSecrets> GetInstalledFlowSecretsAsync()
        {
            if (_developerSecrets != null)
                return _developerSecrets;


            InstalledFlowSecrets secrets = null;
            Uri secretsPath = new Uri(INSTALLED_FLOW_SECRETS_PATH);
            StorageFile file = await StorageFile.GetFileFromApplicationUriAsync(secretsPath);

            //
            // JSON
            //
            string jsonText = await FileIO.ReadTextAsync(file);
            secrets = JsonConvert.DeserializeObject<InstalledFlowSecrets>(jsonText);

            //
            //
            //
            _developerSecrets = secrets;
            return _developerSecrets;
        }
        #endregion









































































































        #region authentication && authorization
        //
        // Returns an authentication token, which will be consumed by TryExchangeForAccessTokensAsync(string).
        // This will bring up a web view.
        // 
        // <see cref="https://github.com/Microsoft/Windows-universal-samples/blob/master/Samples/WebAuthenticationBroker/cs/Scenario4_Google.xaml.cs"/>
        //
        async Task<string> TryGetAuthorizationTokenAsync()
        {
            InstalledFlowSecrets secrets = await this.GetInstalledFlowSecretsAsync();

            //
            // Configure state parameter to prevent XSS
            //
            Random random = new Random((int)DateTime.UtcNow.TimeOfDay.TotalMilliseconds);
            int state = 0;
            for (int i = 0; i < DateTime.UtcNow.TimeOfDay.Seconds; i++)
                state = random.Next();


            //
            // Build the start url for web auth broker
            //
            string startUrl 
                = secrets.Installed.AuthUri
                + "?client_id=" + Uri.EscapeDataString(secrets.Installed.ClientId)
                + "&redirect_uri=" + Uri.EscapeDataString(secrets.Installed.RedirectUris[0])
                + "&response_type=code"
                + "&scope=" + Uri.EscapeDataString(AUTHENTICATION_SCOPES)
                + "&state=" + Uri.EscapeDataString(state.ToString());

            //
            // Build the end url for the web auth broker.
            // The success parameters are appended to the end of this url,
            // which allows the application to seamlessly get the authorization
            // token without asking the user to copy and paste.
            //
            string endUrl = @"https://accounts.google.com/o/oauth2/approval?";

            //
            //
            //
            Uri startUri = new Uri(startUrl, UriKind.Absolute);
            Uri endUri = new Uri(endUrl, UriKind.Absolute);

            try
            {
                //
                // Bring up the web view for the user to authenticate to the service
                //
                WebAuthenticationResult authResult = await WebAuthenticationBroker.AuthenticateAsync(WebAuthenticationOptions.UseTitle, startUri, endUri);

                switch (authResult.ResponseStatus)
                {
                    case WebAuthenticationStatus.Success:
                        //
                        // ResponseData example:     "Success state=1676265812&code=4/c-kI5b5jVGl_NSw7JYmrAmG1h-vH_sY_hJ5FKrbRplA"
                        //
                        ////// Assumes the state parameter will always come before the code parameter.
                        //

                        //
                        // Check the state parameter to prevent XSS.
                        // Update 2016-06-07
                        //      +Regex improved.
                        //
                        //Match s = Regex.Match(authResult.ResponseData, @"(?<=state\x3D).*?(?=\x26)");
                        Match s = Regex.Match(authResult.ResponseData, @"((?<=state\x3D).*?(?=\x26))|((?<=state\x3D).*)");   // the more specific regex should be evaluated first
                        if (s.Success)
                        {
                            if (s.Value != state.ToString())
                            {
#if DEBUG
                                Debug.WriteLine("state (" + state.ToString() + ")");
                                Debug.WriteLine("s.Value (" + s.Value.ToString() + ")");
#endif
                                throw new Exception("State parameter does not match.  Beware XSS.");
                            }


                            //
                            // Get the authorization token
                            //
                            //Match m = Regex.Match(authResult.ResponseData, @"(?<=code\x3D).*");
                            Match m = Regex.Match(authResult.ResponseData, @"((?<=code\x3D).*?(?=\x26))|((?<=code\x3D).*)");    // the more specific regex should be evaluated first
                            if (m.Success)
                                return m.Value;
                            else
                                throw new Exception("Could not get the authorization token code parameter from ResponseData.");
                        }
                        else
                        {
                            //
                            // Do not continue any further
                            //
                            throw new Exception("Could not get state parameter from ResponseData.");
                        }
                            

                    case WebAuthenticationStatus.ErrorHttp:
                    case WebAuthenticationStatus.UserCancel:
                        return null;
                }

                //
                // Fall through
                //
                return null;
            }
            catch (Exception ex)
            {
#if DEBUG
                Debug.WriteLine("TryGetAuthorizationTokenAsync:     something went wrong.");
                Debug.WriteLine(ex.Message);
#endif
                return null;
            }
        }













































































        //
        // A user must obtain an authorization token by authenticating to the service before
        // exchanging the token for access and refresh tokens.
        //
        // It's up to the login function to add the PasswordCredential to the vault
        // and to fill out a new AuthorizedUser.  The reason why the the vault is not
        // opened here is to allow the log in function to check if the user already exists.
        //
        async Task<PasswordCredential> TryExchangeForAccessTokenAsync(string authorizationToken)
        {
            if (string.IsNullOrEmpty(authorizationToken))
                return null;


            InstalledFlowSecrets secrets = await this.GetInstalledFlowSecretsAsync();
            PasswordCredential credential = new PasswordCredential();

            //
            // Use the authorization token to build up responses to fill out a PasswordCredential
            //
            OAuthTokenResponse oauthTokens = null;
            UserInfoResponse userInfo = null;


            using (HttpClient client = new HttpClient())
            {
                #region authorization
                Uri tokenUri = new Uri(secrets.Installed.TokenUri, UriKind.Absolute);

                //
                // Create POST content
                //
                Dictionary<string, string> content = new Dictionary<string, string>();
                content.Add("code", authorizationToken);
                content.Add("client_id", secrets.Installed.ClientId);
                content.Add("client_secret", secrets.Installed.ClientSecret);
                content.Add("redirect_uri", secrets.Installed.RedirectUris[0]);
                content.Add("grant_type", "authorization_code");

                //
                // Url encode the content
                //
                HttpFormUrlEncodedContent body = new HttpFormUrlEncodedContent(content);

                //
                // Send a POST request with the content body
                //
                HttpResponseMessage tokenResponse = null;// = await client.PostAsync(tokenUri, body);

                //
                // Retry
                //
                int retryCount = 2;
                while ((tokenResponse == null || !tokenResponse.IsSuccessStatusCode) & retryCount > 1)
                {
#if DEBUG
                    if (retryCount != 2)
                        Debug.WriteLine("Retrying tokenResponse = await client.PostAsync(tokenUri, body)...");
#endif

                    tokenResponse = await client.PostAsync(tokenUri, body);
                    --retryCount;
                }

                //
                // Break
                //
                if (tokenResponse == null || !tokenResponse.IsSuccessStatusCode)
                    return null;


                //
                // Deserialize the JSON result
                //
                string jsonTokens = await tokenResponse.Content.ReadAsStringAsync();
                oauthTokens = JsonConvert.DeserializeObject<OAuthTokenResponse>(jsonTokens);

                //
                // Break
                //
                if (oauthTokens == null)
                    return null;




                //
                // Start building the PasswordCredential
                //

                //
                // Resource
                //
                credential.Resource 
                    = APP_NAME 
                    + ',' + oauthTokens.TokenType;

                //
                // Password
                //
                credential.Password
                    = oauthTokens.AccessToken
                    + ',' + oauthTokens.RefreshToken
                    + ',' + oauthTokens.ExpiresIn.ToString()
                    + ',' + DateTime.UtcNow.ToString();
                #endregion













                #region userinfo
                Uri userInfoUri = new Uri(USER_INFO_API_URL, UriKind.Absolute);

                //
                // Auth scheme "Bearer"
                //
                HttpCredentialsHeaderValue authHeader = new HttpCredentialsHeaderValue("Bearer", oauthTokens.AccessToken);
                client.DefaultRequestHeaders.Authorization = authHeader;

                //
                // Send a GET request
                //
                HttpResponseMessage userInfoResponse = null;// await client.GetAsync(userInfoUri);

                //
                // Retry
                //
                retryCount = 2;
                while ((userInfoResponse == null || !userInfoResponse.IsSuccessStatusCode) & retryCount > 1)
                {
#if DEBUG
                    if (retryCount != 2)
                        Debug.WriteLine("Retrying userInfoResponse = await client.GetAsync(userInfoUri)...");
#endif

                    userInfoResponse = await client.GetAsync(userInfoUri);
                    --retryCount;
                }

                //
                // Finish the prep on the PasswordCredential
                //
                if (userInfoResponse != null && userInfoResponse.IsSuccessStatusCode)
                {
                    string jsonUserInfo = await userInfoResponse.Content.ReadAsStringAsync();
                    userInfo = JsonConvert.DeserializeObject<UserInfoResponse>(jsonUserInfo);

                    if (userInfo != null)
                    {
                        //
                        // UserName
                        //
                        credential.UserName
                            = userInfo.GivenName
                            + ',' + userInfo.Id
                            + ',' + userInfo.Picture;
                    }
                }
                #endregion
            }


            //
            // Break
            //
            //credential.RetrievePassword();
            //if (string.IsNullOrEmpty(credential.Password))
            //    return null;

            return credential;
        }
        #endregion








































































































        #region revocation
        ///
        /// <summary>
        /// Revocate by passing in access or refresh tokens.  This also removes
        /// the credential within the vault, if found, and also updates
        /// AuthorizedUser, if applicable.
        /// </summary>
        ///

        ///
        /// <remarks>
        /// 
        /// Send a GET request with either a refresh token or an access token.
        /// The associated refresh token is also removed if an access token is revoked.
        /// 
        /// Success response status code is 200.
        /// Error response status code is 400.
        /// 
        /// </remarks>
        ///
        async Task RevokeTokensAsync(params string[] tokens)
        {
            if (tokens?.Length < 1)
                return;

            //
            // Revoking the token from the service should also remove the token
            // from the vault.
            //
            PasswordVault vault = new PasswordVault();
            IReadOnlyList<PasswordCredential> credentials = null;


            //
            //
            //
            using (HttpClient client = new HttpClient())
                foreach (string token in tokens)
                {
                    //
                    // Append the token to the revocation url
                    //
                    Uri revokeUri = new Uri(REVOCATION_API_URL + token);

                    //
                    // Send the revocation request
                    //
                    HttpResponseMessage response = await client.GetAsync(revokeUri);

                    //
                    // Check the status code.
                    // 400 status code typically means the user manually revoked the token
                    // using the service's account management.
                    //
                    if (response.StatusCode == HttpStatusCode.BadRequest)
                    {
                        //
                        // Not much to do here...
                        //
#if DEBUG
                        Debug.WriteLine("This token has already been revoked.");
#endif
                    }

                    //
                    // Check if the token is stored in the vault and remove
                    // the credential if it is found.
                    //
                    credentials = vault.RetrieveAll();
                    if (credentials?.Count > 0)
                        foreach (var cred in credentials)
                        {
                            cred.RetrievePassword();
                            if (cred.Password.Contains(token))
                            {
                                vault.Remove(cred);
                                break;
                            }
                        }

                    //
                    // Check if the token is the current authorized user
                    //
                    if (AuthorizedUser != null 
                        && (!string.IsNullOrEmpty(AuthorizedUser.AccessToken) || !string.IsNullOrEmpty(AuthorizedUser.RefreshToken)))
                        if (token == AuthorizedUser.AccessToken || token == AuthorizedUser.RefreshToken)
                        {
                            AuthorizedUser.AccessToken = string.Empty;
                            AuthorizedUser.DateAcquiredUtc = new DateTime();
                            AuthorizedUser.DisplayName = string.Empty;
                            AuthorizedUser.ExpiresIn = 0;
                            AuthorizedUser.Id = string.Empty;
                            AuthorizedUser.ProfileImageUrl = null;
                            AuthorizedUser.RefreshToken = string.Empty;
                            AuthorizedUser.TokenType = string.Empty;
                            AuthorizedUser = TryGetDefaultAuthorizedUser();
                        }

                }
        }

        #endregion























    }
}
