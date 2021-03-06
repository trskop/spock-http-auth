{-# LANGUAGE CPP #-}
{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}
-- |
-- Module:       $HEADER$
-- Description:  Generic HTTP authentication parsing and serialization
-- Copyright:    (c) 2015, Peter Trško
-- License:      BSD3
--
-- Maintainer:   peter.trsko@gmail.com
-- Stability:    experimental
-- Portability:  CPP, DeriveDataTypeable, DeriveGeneric, NoImplicitPrelude,
--               OverloadedStrings, TupleSections
--
-- Generic HTTP authentication parsing and serialization. This module strictly
-- follows <http://tools.ietf.org/html/rfc2616 RFC 2616: HTTP/1.1> and
-- <http://tools.ietf.org/html/rfc2617 RFC 2617: HTTP Authentication>.
module Web.Spock.HttpAuth.Internal
    (
    -- * HTTP Authentication Scheme
      AuthScheme(..)
    , showAuthScheme
    , parseAuthScheme

    -- * Parse and Serialize Authorization Header Value
    , parseAuthorizationHeaderValue
    , serializeAuthorizationHeaderValue
    )
  where

import Control.Applicative (liftA2)
import Control.Arrow ((<<<), (***))
import Data.Bool (Bool, (&&), otherwise)
import Data.Char (Char)
#if MIN_VERSION_case_insensitive(1,2,0)
import Data.Data (Data)
#endif
import Data.Eq (Eq((==), (/=)))
import Data.Function (($))
import Data.Functor ((<$>))
import Data.Maybe (Maybe(Just, Nothing))
import Data.Monoid ((<>))
import Data.Ord (Ord((<), (>)))
import Data.Typeable (Typeable)
import GHC.Generics (Generic)
import Text.Show (Show)

import Data.CaseInsensitive (CI)
import qualified Data.CaseInsensitive as CI (mk, original)
import Data.Text (Text)
import qualified Data.Text as Text (all, break, dropWhile)


-- | Authentication schemes as understood by
-- <http://tools.ietf.org/html/rfc2617 RFC 2617: HTTP Authentication: Basic and Digest Access Authentication>,
-- but also considering possible extensions.
--
-- In example S3 from Amazon uses its own authentication shceme
-- <http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html Amazon S3: Signing and Authenticating REST Requests>.
--
-- One must not forget NTLM authentication, great summary can be found in article
-- <http://www.innovation.ch/personal/ronald/ntlm.html NTLM Authentication Scheme for HTTP>
-- by Ronald Tschalär.
data AuthScheme
    = AuthBasic
    | AuthDigest
    | AuthOther (CI Text)
  deriving
    ( Eq
    , Generic
    , Show
#if MIN_VERSION_case_insensitive(1,2,0)
    , Data
#endif
    , Typeable
    )

-- | Get 'Text' representation of 'AuthScheme'. Result for 'AuthBasic' and
-- 'AuthDigest' is corresponding Authentication Scheme from HTTP vocabulary,
-- i.e. @\"Basic\"@ and @\"Digest\"@, respectively. For @'AuthOther' someAuth@
-- it is the value @someAuth@ unwrapped from 'CI' as original case unfolded
-- value.
showAuthScheme :: AuthScheme -> Text
showAuthScheme AuthBasic          = "Basic"
showAuthScheme AuthDigest         = "Digest"
showAuthScheme (AuthOther scheme) = CI.original scheme

-- | Create value of @Authorization@ header. Implemented as:
--
-- @
-- 'showAuthScheme' scheme '<>' \" \" '<>' credentials
-- @
serializeAuthorizationHeaderValue
    :: AuthScheme
    -> Text
    -- ^ Credentials for the specified 'AuthScheme'.
    -> Text
serializeAuthorizationHeaderValue scheme credentials =
    showAuthScheme scheme <> " " <> credentials



-- | Parse value of @Authorization@ header. In example, if we have header like
-- this:
--
-- @
-- Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
-- @
--
-- this function parses the value portion of the above HTTP header:
--
-- >>> parseAuthorizationHeaderValue "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ=="
-- Just (AuthBasic, "QWxhZGRpbjpvcGVuIHNlc2FtZQ==")
--
-- Notice that the /credentials portion/ is kept unchanged, not even Base64
-- decoded, since that encoding may not be used by custom authentication
-- scheme.
--
-- Relevant parts of
-- <http://tools.ietf.org/html/rfc2617#section-1.2 RFC 2617: HTTP Authentication: Basic and Digest Access Authentication: 1.2 Access Authentication Framework>
--
-- > auth-scheme    = token
-- > auth-param     = token "=" ( token | quoted-string )
-- > credentials    = auth-scheme #auth-param
--
-- But in RFC 2617 we can see the definition of @credentials@ as:
--
-- > credentials    = auth-scheme ( token | quoted-string | #auth-param )
--
-- Since credentials part can be that diverse, this function only parses scheme
-- portion (see 'parseAuthScheme') and leading spaces are removed from the
-- rest, but otherwise it is returned as it was received.
--
-- >>> parseAuthorizationHeaderValue "Foo alpha"
-- Just (AuthOther "Foo","alpha")
parseAuthorizationHeaderValue :: Text -> Maybe (AuthScheme, Text)
parseAuthorizationHeaderValue input = (,credentials) <$> maybeScheme
  where
    (maybeScheme, credentials) = parseAuthScheme *** Text.dropWhile (== ' ')
        <<< Text.break (== ' ') $ input

-- | Parse authentication scheme portion of @Authorization@ header. In example,
-- if we have header like this:
--
-- @
-- Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
-- @
--
-- this function parses /Authentication Scheme portion/ of the value part of
-- the above HTTP header:
--
-- >>> parseAuthScheme "Basic"
-- Just AuthBasic
--
-- Note that this function checks if /Authentication Scheme portion/ is
-- correctly formated and contains only allowed characters. If it is not, then
-- 'Nothing' is returned.
--
-- Relevant parts of
-- <http://tools.ietf.org/html/rfc2617#section-1.2 RFC 2617: HTTP Authentication: Basic and Digest Access Authentication: 1.2 Access Authentication Framework>
--
-- > auth-scheme    = token
--
-- Relevant parts of
-- <http://tools.ietf.org/html/rfc2616#section-2.2 RFC 2616: Hypertext Transfer Protocol -- HTTP/1.1: 2.2 Basic Rules>:
--
-- > token          = 1*<any CHAR except CTLs or separators>
-- > CHAR           = <any US-ASCII character (octets 0 - 127)>
-- > CTL            = <any US-ASCII control character
-- >                  (octets 0 - 31) and DEL (127)>
-- > separators     = "(" | ")" | "<" | ">" | "@"
-- >                | "," | ";" | ":" | "\" | <">
-- >                | "/" | "[" | "]" | "?" | "="
-- >                | "{" | "}" | SP  | HT
-- > SP             = <US-ASCII SP, space (32)>
-- > HT             = <US-ASCII HT, horizontal-tab (9)>
-- > <">            = <US-ASCII double-quote mark (34)>
parseAuthScheme :: Text -> Maybe AuthScheme
parseAuthScheme txt
  | validInput = Just $ parseAuthScheme' (CI.mk txt)
  | otherwise  = Nothing
  where
    validInput = Text.all validChars txt

    parseAuthScheme' scheme
      | scheme == "basic"  = AuthBasic
      | scheme == "digest" = AuthDigest
      | otherwise          = AuthOther scheme

    validChars :: Char -> Bool
    validChars = (> char31) <&&> (< del)
        <&&> (/= '(') <&&> (/= ')') <&&> (/= '<') <&&> (/= '>')  <&&> (/= '@')
        <&&> (/= ',') <&&> (/= ';') <&&> (/= ':') <&&> (/= '\\') <&&> (/= '\"')
        <&&> (/= '/') <&&> (/= '[') <&&> (/= ']') <&&> (/= '?')  <&&> (/= '=')
        <&&> (/= '{') <&&> (/= '}') <&&> (/= ' ')

    char31, del :: Char
    char31 = '\x1F' -- US (unit separator) = 31 dec
    del    = '\x7f' -- DEL = 127 dec

    (<&&>) = liftA2 (&&)
