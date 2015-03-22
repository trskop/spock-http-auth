{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
module Web.Spock.HttpAuth
   (
     AuthScheme(..)
   , requireAuth

   -- * HTTP Basic Authentication
   , basicAuthFailed
   , parseBasicAuth
   )
  where

import Control.Applicative (liftA2)
import Control.Arrow (Arrow((***), second), (<<<))
import Control.Monad (liftM)
import Data.Data (Data)
import Data.Functor ((<$>))
import Data.Monoid ((<>))
import Data.Typeable (Typeable)
import GHC.Generics (Generic)

import Control.Monad.Trans (MonadIO, MonadTrans(lift))
import Data.CaseInsensitive (CI)
import qualified Data.CaseInsensitive as CI
import Data.Text (Text)
import qualified Data.Text as Text (break, drop, strip)
import qualified Data.Text.Encoding as Text (decodeUtf8, encodeUtf8)

import Data.ByteString.Base64 as Base64 (decodeLenient)
import Network.HTTP.Types.Status (unauthorized401)
import Web.Spock.Shared

import Web.Spock.HttpAuth.Internal
    ( AuthScheme(..)
    , parseAuthorizationHeaderValue
    )


-- | Parametrised authentication boilerplate.
requireAuth
    :: MonadIO m
    => (AuthScheme -> Text -> Maybe cred)
    -- ^ Parse credentials further. This part may also failed, which will
    -- result in result in authentication failure.
    -> (cred -> m (Maybe info))
    -- ^ Verify credentials and possibly return further information, e.g. user
    -- data retrieved from database.
    -> ActionT m a
    -- ^ Action performed on authentication failure.
    -> (info -> ActionT m a)
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
        (parseAuthorizationHeaderValue =<<) `liftM` header "Authorization"

-- {{{ HTTP Basic Authentication ----------------------------------------------

basicAuthFailed :: MonadIO m => Text -> ActionT m a
basicAuthFailed realm = do
    setStatus unauthorized401
    setHeader "WWW-Authenticate" $ "Basic realm=\"" <> realm <> "\""
    text "Authentication required."

parseBasicAuth :: AuthScheme -> Text -> Maybe (Text, Text)
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
