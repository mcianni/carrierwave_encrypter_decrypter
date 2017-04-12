module Openssl
  module Aes
    def self.encrypt_for(obj)
      model = obj.model
      mounted_as = obj.mounted_as
      cipher = OpenSSL::Cipher.new("AES-#{Carrierwave::EncrypterDecrypter.configuration.key_size}-CBC")
      cipher.encrypt
      iv = cipher.random_iv
      model.iv = iv
      key = cipher.random_key
      model.key = key
      model.save!

      original_file_path = File.expand_path(obj.store_path, obj.root)
      encrypted_file_path = original_file_path + '.enc'
      buf = ""
      File.open(encrypted_file_path, "wb") do |outf|
        File.open(model.send(mounted_as).path, "rb") do |inf|
          while inf.read(4096, buf)
            outf << cipher.update(buf)
          end
          outf << cipher.final
        end
      end
      File.unlink(model.send(mounted_as).path)
    end

    def self.decrypt_for(obj,opts)
      model = obj
      mounted_as = opts[:mounted_as]
      cipher = OpenSSL::Cipher.new("AES-#{Carrierwave::EncrypterDecrypter.configuration.key_size}-CBC")
      cipher.decrypt
      cipher.iv = model.iv
      cipher.key = model.key
      buf = ""

      original_file_path  = obj.send(mounted_as).root.join obj.send(mounted_as).path
      encrypted_file_path = original_file_path.to_s + '.enc'

      File.open(original_file_path, "wb") do |outf|
        File.open(encrypted_file_path, "rb") do |inf|
          while inf.read(4096, buf)
            outf << cipher.update(buf)
          end
          outf << cipher.final
        end
      end
    end
  end
end
