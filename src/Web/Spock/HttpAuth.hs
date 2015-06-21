{-# LANGUAGE CPP #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
-- |
-- Module:       $HEADER$
-- Description:  HTTP authentication framework for Spock
-- Copyright:    (c) 2015 Peter Trško
-- License:      BSD3
--
-- Maintainer:   peter.trsko@gmail.com
-- Stability:    experimental
-- Portability:  CPP, NoImplicitPrelude, OverloadedStrings
--
-- HTTP authentication framework for Spock.
module Web.Spock.HttpAuth
   (
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
        (parseAuthorizationHeaderValue =<<) <$> header "Authorization"

#if !APPLICATIVE_MONAD
    -- Trying hard to avoid adding unnecessary Applicative constraint, but its
    -- starting to get ridiculous. Thank gods for AMP in GHC 7.10.
    (<$>) = liftM
#endif

-- {{{ HTTP Basic Authentication ----------------------------------------------

basicAuthFailed :: MonadIO m => Text -> ActionT m a
basicAuthFailed realm = do
    setStatus unauthorized401
    setHeader "WWW-Authenticate" $ "Basic realm=\"" <> realm <> "\""
    text "401 Unauthorized"

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
