/*
    Date      :     Monday, June 13, 2016
    Author    :     pdcdeveloper (https://github.com/pdcdeveloper)
    Objective :     
    Version   :     1.0
*/




using QPLib.Base;
using System;


namespace QPGoogleAPI.OAuth.Models
{
    ///
    /// <summary>
    /// Contains all the necessary data required for any authenticated action
    /// a user might take and also contains information about the authenticated
    /// user.
    /// </summary>
    /// 

    ///
    /// <remarks>
    /// 
    /// Because PasswordCredential has too few properties.
    /// 
    /// Do not use this for storage, instead use this as
    /// the available credential while a user is still logged in.
    /// 
    /// This class is not encrypted automatically like
    /// PasswordCredential, so clear it out manually
    /// whenever the app gets suspended after storing
    /// the values within a PasswordCredential.
    /// 
    /// This lays flat all the necessary info from a TokenResponse
    /// and a PlusPersonResponse.
    /// 
    /// </remarks>
    ///
    public class AuthorizedUser : NotifyPropertyChangedBase
    {
        #region TokenResponse - all of it plus some extra to make refresh tokens easier to consume

        string _accessToken;
        public string AccessToken
        {
            get { return _accessToken; }
            set
            {
                _accessToken = value;
                OnPropertyChanged();
                OnSingletonPropertyChanged();
            }
        }


        string _tokenType;
        public string TokenType
        {
            get { return _tokenType; }
            set
            {
                _tokenType = value;
                OnPropertyChanged();
            }
        }


        int? _expiresIn;
        public int? ExpiresIn
        {
            get { return _expiresIn; }
            set
            {
                _expiresIn = value;
                OnPropertyChanged();
            }
        }

        string _refreshToken;
        public string RefreshToken
        {
            get { return _refreshToken; }
            set
            {
                _refreshToken = value;
                OnPropertyChanged();
            }
        }



        DateTime? _dateAcquiredUtc;
        public DateTime? DateAcquiredUtc
        {
            get { return _dateAcquiredUtc; }
            set
            {
                _dateAcquiredUtc = value;
                OnPropertyChanged();
            }
        }


        public bool IsAccessTokenExpired
        {
            get
            {
                if (this.DateAcquiredUtc == null || ExpiresIn == 0)
                    return false;

#if DEBUG
                TimeSpan timeBuffer = TimeSpan.FromSeconds(3570);       // refresh within the next 30 seconds
#else
                TimeSpan timeBuffer = TimeSpan.FromSeconds(300);        // refresh the token if it's going to expire within the next 5 minutes
#endif

                DateTime expirationDate = DateAcquiredUtc.Value + TimeSpan.FromSeconds(ExpiresIn.Value);

                if (DateTime.UtcNow + timeBuffer >= expirationDate)
                    return true;
                return false;
            }
        }

        #endregion










        #region PlusPersonResponse - currently only the most important stuff

        string _displayName;
        public string DisplayName
        {
            get { return _displayName; }
            set
            {
                _displayName = value;
                OnPropertyChanged();
            }
        }


        string _id;
        public string Id
        {
            get { return _id; }
            set
            {
                _id = value;
                OnPropertyChanged();
            }
        }


        string _profileImageUrl;
        public string ProfileImageUrl
        {
            get { return _profileImageUrl; }
            set
            {
                _profileImageUrl = value;
                OnPropertyChanged();
            }
        }


        #endregion
    }
}
