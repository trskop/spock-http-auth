{-# LANGUAGE CPP #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module:       $HEADER$
-- Description:  HTTP authentication framework for Spock
-- Copyright:    (c) 2015, Peter Trško
-- License:      BSD3
--
-- Maintainer:   peter.trsko@gmail.com
-- Stability:    experimental
-- Portability:  CPP, NoImplicitPrelude, OverloadedStrings
--
-- HTTP authentication framework for Spock.
module Web.Spock.HttpAuth
   (
   -- * Generic HTTP Authentication
     AuthScheme(..)
   , requireAuth

   -- * HTTP Basic Authentication
   , basicAuthFailed
   , parseBasicAuth
   )
  where

#if APPLICATIVE_MONAD
import Control.Applicative ((<$>))
#endif
import Control.Arrow (Arrow(second))
import Control.Monad
    ( (=<<)
#if !APPLICATIVE_MONAD
    , liftM
#endif
    )
import Data.Eq (Eq((==)))
import Data.Function ((.), ($), const)
import Data.Maybe (Maybe(Just, Nothing))
import Data.Monoid ((<>))

import Control.Monad.Trans (MonadIO, MonadTrans(lift))
import Data.Text (Text)
import qualified Data.Text as Text (break, drop, strip)
import qualified Data.Text.Encoding as Text (decodeUtf8, encodeUtf8)

import Data.ByteString.Base64 as Base64 (decodeLenient)
import Network.HTTP.Types.Status (unauthorized401)
import Web.Spock.Shared (ActionT, header, setHeader, setStatus, text)

import Web.Spock.HttpAuth.Internal
    ( AuthScheme(AuthBasic, AuthDigest, AuthOther)
    , parseAuthorizationHeaderValue
    )


-- {{{ Generic HTTP Authentication --------------------------------------------

-- | Parametrised authentication boilerplate. Should work for both Basic and
-- Digest authentication, as well as any other custom defined authentication.
requireAuth
    :: MonadIO m
    => (AuthScheme -> Text -> Maybe cred)
    -- ^ Parse credentials further. This part may also fail, which will
    -- result in authentication failure.
    -> (cred -> m (Maybe info))
    -- ^ Verify credentials and possibly return further information, e.g. user
    -- data retrieved from database.
    -> ActionT m a
    -- ^ Action performed on authentication failure.
    -> (info -> ActionT m a)
    -- ^ Action performed on authentication success.
    -> ActionT m a
requireAuth parseCred verifyCred onAuthFailed action = do
    maybeAuthHeader <- authorizationHeader
    case maybeAuthHeader of
        Nothing                    -> onAuthFailed
            -- No "Authorization" header or unable to parse credentials
            -- => unauthorized
        Just (authScheme, rawCred) -> case parseCred authScheme rawCred of
            Nothing   -> onAuthFailed
                -- Unable to parse credentials => unauthorized
            Just cred -> do
                maybeInfo <- lift $ verifyCred cred
                case maybeInfo of
                    Nothing   -> onAuthFailed
                        -- Unable to verify credentials => unauthorized
                    Just info -> action info
  where
    authorizationHeader =
        (parseAuthorizationHeaderValue =<<) <$> header "Authorization"

#if !APPLICATIVE_MONAD
    -- Trying hard to avoid adding unnecessary Applicative constraint, but its
    -- starting to get ridiculous. Thank gods for AMP in GHC 7.10.
    (<$>) = liftM
#endif

-- {{{ HTTP Basic Authentication ----------------------------------------------

-- | Standard, HTTP protocol defined, reaction to HTTP Basic authentication
-- failre:
--
-- * Status code is set to: @401 Unauthorized@
-- * Header @WWW-Authenticate@ is present and has value
--   @Basic realm=\"$realm\"@.
-- * @Content-Type@ is set to @text/plain@ and body contains text
--   @401 Unauthorized@. This bit is not mandated by the HTTP standard.
basicAuthFailed
    :: MonadIO m
    => Text
    -- ^ Authorization realm, See also
    -- <https://tools.ietf.org/html/rfc2617#section-1.2 RFC 2617: 1.2 Access Authentication Framework>
    -> ActionT m a
basicAuthFailed realm = do
    setStatus unauthorized401
    setHeader "WWW-Authenticate" $ "Basic realm=\"" <> realm <> "\""
    text "401 Unauthorized"

-- | Parse content of @Authorization@ header and expect it to contain
-- information defined by HTTP Basic Authentication.
parseBasicAuth
    :: AuthScheme
    -- ^ Expected to be 'AuthBasic', otherwise 'Nothing' is returned.
    -> Text
    -- ^ Content of @Authentication@ header to be parsed in to username and
    -- password.
    -> Maybe (Text, Text)
    -- ^ Returns @'Just' (username, password)@, iff authentication is HTTP
    -- Basic Authentication, and also content of @Authentication@ is parsable
    -- according to HTTP Specification. In any other case 'Nothing' is
    -- returned.
parseBasicAuth authScheme = case authScheme of
    AuthBasic -> Just . parseBasicAuth'
    _         -> const Nothing
  where
    parseBasicAuth' :: Text -> (Text, Text)
    parseBasicAuth' = splitCred . onBS Base64.decodeLenient . Text.strip

    onBS = (Text.decodeUtf8 .) . (. Text.encodeUtf8)

    splitCred :: Text -> (Text, Text)
    splitCred = second (Text.drop 1) . Text.break (== ':')

-- }}} HTTP Basic Authentication ----------------------------------------------
