require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class Fedena < OmniAuth::Strategies::OAuth2
      option :name, :fedena

      option :client_options, {
        :site => "http://fedena.com"
      }

      uid { raw_info["username"] }

      info do
        {
          :email => raw_info["email"],
          :username => raw_info["username"],
          :first_name => raw_info["first_name"],
          :last_name => raw_info["last_name"],
          :user_type => raw_info["user_type"]
        }
      end

      def build_access_token
        Rails.logger.debug "Omniauth build access token "
        options.auth_token_params.merge!(:header_format=>"Token token=\"%s\"")
        verifier = request.params["code"]
        super
      end
      def callback_url
        super.gsub(/\?.*/, '')
      end

      def raw_info
        @raw_info ||= Hash.from_xml(access_token.get('/api/users/'+access_token.params["user_info"]["username"]).body)["user_detail"]["user"]
      end
    end
  end
end
