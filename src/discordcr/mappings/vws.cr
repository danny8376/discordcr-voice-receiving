module Discord
  # :nodoc:
  module VWS
    struct SpeakingPayload
      include JSON::Serializable

      module SpeakingConverter
        def self.from_json(parser)
          raw = parser.read_int
          raw == 1
        end

        def self.to_json(value, builder)
          (value ? 1 : 0).to_json(builder)
        end
      end

      property user_id : Snowflake
      property ssrc : UInt32
      @[JSON::Field(key: "speaking", converter: Discord::VWS::SpeakingPayload::SpeakingConverter)]
      property speaking : Bool
      property delay : Int32? # prevent error

      @user_id = Snowflake.new(0) # prevent error
      @ssrc = 0 # prevent error

      def initialize(@user_id, @ssrc, @speaking)
      end
    end
  end
end

