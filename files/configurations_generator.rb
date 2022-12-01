#
# The MIT License
# Copyright (c) 2019- Nordic Institute for Interoperability Solutions (NIIS)
# Copyright (c) 2018 Estonian Information System Authority (RIA),
# Nordic Institute for Interoperability Solutions (NIIS), Population Register Centre (VRK)
# Copyright (c) 2015-2017 Estonian Information System Authority (RIA), Population Register Centre (VRK)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

require 'time'
require 'net/http'
require 'socket'
require 'digest'
require 'base64'
require 'openssl'

require 'tmpdir'
require 'fileutils'

require 'common-ui/io_utils'
require 'common-ui/cert_utils'

java_import Java::ee.ria.xroad.common.conf.globalconf.ConfigurationConstants
java_import Java::ee.ria.xroad.common.util.HashCalculator
java_import Java::ee.ria.xroad.common.SystemProperties

# The class is responsible for generating the global configuration versions
# and distributing them
class ConfigurationsGenerator

  OLD_CONF_PRESERVING_SECONDS = 600

  def initialize
    Rails.logger.debug("Initialize ConfigurationsGenerator")

    # The central server can generate multiple versions of global configuration
    # At the moment it has capability to generate only V2 global conf
    # New global conf generators can be added to the array
    # The versions generated can be controlled with the system parameter
    @conf_generators = [ConfV2Generator.new()].select { | generator |
        generator.getVersion >= SystemProperties::get_minimum_central_server_global_configuration_version}

    Rails.logger.debug("Initialization complete")
  end

  def create_distributable_configuration
    Rails.logger.debug("Generate configurations")

    @conf_generators.each do |generator|
      Rails.logger.debug("Generate v#{generator.getVersion} private parameters")
      private_parameters_xml = generator.generatePrivateParameters()

      Rails.logger.debug("Validate v#{generator.getVersion} private parameters")
      generator.validatePrivateParameters(private_parameters_xml)

      Rails.logger.debug("Generate v#{generator.getVersion} shared parameters")
      shared_parameters_xml = generator.generateSharedParameters()

      Rails.logger.debug("Validate v#{generator.getVersion} shared parameters")
      generator.validateSharedParameters(shared_parameters_xml)

      Rails.logger.debug("Save v#{generator.getVersion} private parameters to database")
      DistributedFiles.save_configuration_part(ConfigurationConstants::CONTENT_ID_PRIVATE_PARAMETERS,
          ConfigurationConstants::FILE_NAME_PRIVATE_PARAMETERS, private_parameters_xml, generator.getVersion)

      Rails.logger.debug("Save v#{generator.getVersion} shared parameters to database")
      DistributedFiles.save_configuration_part(ConfigurationConstants::CONTENT_ID_SHARED_PARAMETERS,
          ConfigurationConstants::FILE_NAME_SHARED_PARAMETERS, shared_parameters_xml, generator.getVersion)
    end

    Rails.logger.info("Configuration generation: success")
  rescue
    Rails.logger.error("Failed to generate global configuration: #{$!.message}")
    raise "Failed to generate valid global configuration: #{$!.message}"
  end

  def distribute_configuration
    Rails.logger.debug("Distribute configurations")

    init_generated_conf_locations
    save_distributed_files_to_disk

    @conf_generators.each do |generator|
      process_internal_configuration(get_temp_internal_directory,
          DistributedFiles.get_internal_source_content_identifiers, "/V#{generator.getVersion}", generator.getVersion)
      process_external_configuration(get_temp_external_directory,
          [ConfigurationConstants::CONTENT_ID_SHARED_PARAMETERS], "/V#{generator.getVersion}", generator.getVersion)
    end

    clean_up_old_configurations
    serve_configurations

    Rails.logger.info("Configuration distribution: success")
  rescue
    Rails.logger.error("#{$!.message}")
    raise $!
  end

  def init_generated_conf_locations
    @generation_timestamp = Time.now().utc().strftime("%Y%m%d%H%M%S%N")
    @conf_locations = Hash.new

    @conf_generators.each do |generator|
      new_conf_dir = "#{get_generated_conf_dir()}/V#{generator.getVersion}/#@generation_timestamp"
      FileUtils.mkdir_p(new_conf_dir, :mode => 0755)
      @conf_locations.store(generator.getVersion, new_conf_dir)
    end

    Rails.logger.debug("Created configuration directories")
  rescue
    raise "Failed to initialize generated configuration location: '#{$!.message}'"
  end

  def get_generated_conf_dir
    return Java::ee.ria.xroad.common.SystemProperties.getCenterGeneratedConfDir()
  end

  # Save distributed files to disk
  def save_distributed_files_to_disk
    @conf_generators.each do |generator|
      Rails.logger.debug("Writing V#{generator.getVersion} configuration to disk")

      distributed_files = DistributedFiles.get_all(generator.getVersion)

      write_public_copy(distributed_files, @conf_locations.fetch(generator.getVersion))

      if generator.isCurrentVersion?
        write_local_copy(distributed_files)
      end

      Rails.logger.debug("Wrote configuration successfully")
    end

    write_local_instance

    Rails.logger.debug("All configurations were written to disk successfully")
  rescue
    raise "Failed to save configuration to disk: #{$!.message}"
  end

  def write_public_copy(distributed_files, conf_dir)
    distributed_files.each do |file|
      target_file = "#{conf_dir}/#{file.file_name}"
      write_to_disk(target_file, file.file_data)
    end
  end

  # Creates a local copy of the global conf files to /etc/xroad/globalconf.
  # This is necessary so that central server Java components could easily read
  # the global configuration through the same API as the security server.
  def write_local_copy(distributed_files)
    instance_identifier = SystemParameter.instance_identifier
    target_directory = "#{get_local_conf_directory()}/#{instance_identifier}"

    # Create the target directory, if it does not exist.
    FileUtils.mkdir_p(target_directory, :mode => 0755)

    target_dist_files = []

    # Write distributed files with corresponding metadata files.
    distributed_files.each do |file|
      target_file = "#{target_directory}/#{file.file_name}"
      write_to_disk(target_file, file.file_data)

      # Create a dummy metadata so that ConfigurationDirectory could read the conf.
      conf_expire_time = Time.now + SystemParameter.conf_expire_interval_seconds
      dummy_metadata = "{\"contentIdentifier\":\"DUMMY\","\
        "\"instanceIdentifier\":\"#{instance_identifier}\",\"contentFileName\":null,"\
        "\"contentLocation\":\"\""\
        ",\"expirationDate\":\"#{conf_expire_time.utc().strftime "%Y-%m-%dT%H:%M:%SZ"}\"}"
      write_to_disk("#{target_file}.metadata", dummy_metadata)

      target_dist_files.push(target_file)
    end

    # Write 'files' file needed for globalconf validation checking.
    target_file = "#{get_local_conf_directory()}/files"
    write_to_disk(target_file, target_dist_files.join("\n"))

    # Delete lost distributed files.
    delete_files = Dir.entries(target_directory).select {
      |f| File.file?(File.join(target_directory, f)) && !f.end_with?(".metadata")
    } .map {|f| File.join(target_directory, f)} - target_dist_files

    Rails.logger.info("Remove lost distributed files #{delete_files}") if delete_files.length > 0

    delete_files.each do |file|
       begin
         FileUtils.remove_entry_secure(file, :force => true)
         FileUtils.remove_entry_secure(file + ".metadata", :force => true)
       rescue
           Rails.logger.error("Failed to remove old globalconf local file '#{file}'':\n#{$!.message}")
       end
    end
  end

  def write_local_instance
    instance_identifier = SystemParameter.instance_identifier
    target_file = "#{get_local_conf_directory()}/instance-identifier"
    write_to_disk(target_file, instance_identifier)
  end

  def write_to_disk(target_file, file_data)
    Rails.logger.debug("Writing data to '#{target_file}'")

    encoded_output = file_data.force_encoding(Rails.configuration.encoding)

    writing_process = Proc.new {|f| f.write(encoded_output)}
    CommonUi::IOUtils.write_public(target_file, writing_process)
  rescue
    Rails.logger.error("Failed to save distributed file #{target_file} to disk: #{$!.message}")
    raise $!
  end

  def federation_switched_on?
    Java::ee.ria.xroad.common.SystemProperties::getCenterTrustedAnchorsAllowed
  end

  def process_internal_configuration(target_file, internal_source_content_identifiers, path_suffix='', version=1)
    Rails.logger.debug("process_internal_configuration() - start")

    signing_key = ConfigurationSource.get_internal_signing_key

    unless signing_key
      raise "Internal source must have an active key, but there is none."
    end

    ConfigurationSigningKey.validate(signing_key)

    Rails.logger.debug("Generating internal conf to: #{target_file}")

    signed_file = sign(signing_key.key_identifier, internal_source_content_identifiers, version)

    distribute(signed_file, target_file, signing_key.cert, path_suffix)

    GlobalConfSigningLog.write("Internal configuration distributed successfully.\n", get_internal_directory)

    Rails.logger.debug("process_internal_configuration() - finished")
  rescue
    GlobalConfSigningLog.write(GlobalConfSigningLog.get_exception_ctx($!), get_internal_directory)

    raise "Processing internal configuration failed: #{$!.message}"
  end

  def process_external_configuration(target_file, allowed_content_identifiers, path_suffix='', version=1)
    Rails.logger.debug("process_external_configuration() - start")

    signing_key = ConfigurationSource.get_external_signing_key

    unless signing_key
      if federation_switched_on?
        raise "Active external signing key must exist if federation is switched on, but there is none."
      else
        return
      end
    end

    ConfigurationSigningKey.validate(signing_key)

    Rails.logger.debug("Generating external conf to: #{target_file}")

    signed_file = sign(signing_key.key_identifier, allowed_content_identifiers, version)
    distribute(signed_file, target_file, signing_key.cert, path_suffix)

    update_subsystems
    GlobalConfSigningLog.write("External configuration distributed successfully.\n", get_external_directory)

    Rails.logger.debug("process_external_configuration() - finished")
  rescue
    GlobalConfSigningLog.write(GlobalConfSigningLog.get_exception_ctx($!), get_external_directory)

    raise "Processing external configuration failed: #{$!.message}"
  end

  def sign(signing_key_id, allowed_content_identifiers = nil, version=1)
    Rails.logger.debug("Generating signed distributed files")

    if signing_key_id.blank?
      raise "Cannot sign without signing key!"
    end

    begin
      get_signer(signing_key_id, allowed_content_identifiers).sign(version)
    rescue
      raise "Failed to sign files: #{$!.message}"
    end
  end

  def distribute(signed_file, target_file, signing_cert, path_suffix)
    Rails.logger.debug("Distributing files to #{target_file}")

    if target_file.blank?
      raise "Distribution target file must not be blank!"
    end

    if signing_cert.blank?
      raise "Cannot distribute configuration without verification cert!"
    end

    begin
      get_distributor(target_file, signing_cert, path_suffix).distribute(signed_file)
    rescue
      raise "Failed to distribute files: #{$!.message}"
    end
  end

  def serve_configurations
    generated_conf_dir = get_generated_conf_dir

    @conf_generators.each do |generator|
      internal_directory_path = "#{generated_conf_dir}/V#{generator.getVersion}/#{get_internal_directory}"
      Rails.logger.debug("Serving internal conf on path '#{internal_directory_path}'")

      begin
        FileUtils.mv("#{generated_conf_dir}/V#{generator.getVersion}/#{get_temp_internal_directory}",
                    internal_directory_path)
      rescue
        raise "Failed to serve internal configuration: #{$!.message}"
      end

      next unless can_serve_external_directory(generator.getVersion)
      external_directory_path = "#{generated_conf_dir}/V#{generator.getVersion}/#{get_external_directory}"
      Rails.logger.debug("Serving external conf on path '#{external_directory_path}'")

      begin
        FileUtils.mv("#{generated_conf_dir}/V#{generator.getVersion}/#{get_temp_external_directory}",
                    external_directory_path)
      rescue
        raise "Failed to serve external configuration: #{$!.message}"
      end
    end
  end

  def can_serve_external_directory(version)
    File.exists?("#{get_generated_conf_dir}/V#{version}/#{get_temp_external_directory}")
  end

  def clean_up_old_configurations
    @conf_generators.each do |generator|
      old_entries = Dir.glob("#{get_generated_conf_dir()}/V#{generator.getVersion}/*").select do |f|
        File.mtime(f) < (Time.now() - (OLD_CONF_PRESERVING_SECONDS))
      end

      old_entries.each do |each|
        next unless is_global_conf_dir?(each)
        FileUtils.remove_entry_secure(each, :force => true)
      end
    end
  rescue
    Rails.logger.error("Failed to clean up old configuration, message:\n#{$!.message}")
  end

  def is_global_conf_dir?(file)
    # We assume directory with name consisting of numbers only.
    File.directory?(file) && File.basename(file) =~ /\A\d+\z/
  end

  def get_signer(sign_key_id, allowed_content_identifiers)
    conf_expire_time = Time.now + SystemParameter.conf_expire_interval_seconds
    hash_calculator = HashCalculator.new(SystemParameter.conf_hash_algo_uri)
    sign_digest_algo_id = SystemParameter::conf_sign_digest_algo_id

    content_builder = DirectoryContentBuilder.new(conf_expire_time, hash_calculator, @generation_timestamp,
            allowed_content_identifiers)

    return DirectorySigner.new(sign_key_id, sign_digest_algo_id, content_builder)
  end

  def get_distributor(target_file, signing_cert, path_suffix='')
    hash_calculator = HashCalculator.new(SystemParameter.conf_sign_cert_hash_algo_uri)

    SignedDirectoryDistributor.new("#{get_generated_conf_dir()}#{path_suffix}", target_file, hash_calculator,
            signing_cert)
  end

  def get_generated_conf_dir
    return Java::ee.ria.xroad.common.SystemProperties.getCenterGeneratedConfDir()
  end

  def get_temp_internal_directory
    return "#{get_internal_directory()}.tmp"
  end

  def get_temp_external_directory
    return "#{get_external_directory()}.tmp"
  end

  def get_internal_directory
    return Java::ee.ria.xroad.common.SystemProperties.getCenterInternalDirectory()
  end

  def get_external_directory
    return Java::ee.ria.xroad.common.SystemProperties.getCenterExternalDirectory()
  end

  def get_local_conf_directory
    return Java::ee.ria.xroad.common.SystemProperties.getConfigurationPath()
  end

  def remove_conf_locations
    @conf_locations.each_value do |value|
      FileUtils.remove_entry_secure(value, :force => true)
    end
  rescue
    Rails.logger.error("Failed to remove new conf directory, message:\n#{$!.message}")
  end


  def get_data(url)
    uri = URI.parse(url)
    response = Net::HTTP.get_response(uri)
    data = response.body
  end

  def process_sharedparams(data)

   edit = ""
   arr = data.split("\n")
   found = data.include?("<username>")

     if found
         for element in arr
           if  element.include?("<username>")==false && element.include?("<password>")==false && element.include?("<oidPolicy>")==false
            edit += element + ("\n")
           end
         end
     else
         parameters = "        <username></username>\n        <password></password>\n        <oidPolicy></oidPolicy>\n"
         for element in arr
           if  element.include?("</approvedTSA>")==true
             edit += parameters
             edit += "</approvedTSA>"
           else
             edit += element + ("\n")
           end
         end
     end

    return edit

  end

  def load_anchor(name_anchor)
        anchor = File.read '/var/lib/xroad/public/anchors/' + name_anchor
  end

  def edit_anchor(anchor)

        ip_address = Socket.ip_address_list.find { |ai| ai.ipv4? && !ai.ipv4_loopback? }.ip_address
        key_cert   = File.read '/etc/xroad/ssl/internal.crt'
        key_cert   = (((key_cert.gsub "\n","").sub "-----BEGIN CERTIFICATE-----","").sub "-----END CERTIFICATE-----","").strip
        dec64    = Base64.decode64(key_cert)
        hash512  = OpenSSL::Digest::SHA512.digest(dec64)
        key_hash = Base64.encode64(hash512)
        key_hash = key_hash.gsub "\n",""
        arr_anchor       = anchor.split("\n")
        instance         = ((arr_anchor[3].sub "<instanceIdentifier>","").sub "</instanceIdentifier>","").strip
        externalconf_url = arr_anchor[5]
        externalconf_url = ((externalconf_url.sub "<downloadURL>","").sub "</downloadURL>","").strip
        arr_anchor[5]    = "        <downloadURL>http://" + ip_address + "/externalconf_" + instance + "</downloadURL>"
        arr_anchor[6]    = "        <verificationCert>" + key_cert + "</verificationCert>"
        externalconf_data = get_data(externalconf_url)
        arr = externalconf_data.split("\n")
        shared_params_url    = externalconf_url.sub "/externalconf","" + (arr[13].sub "Content-location: ","")
        shared_params_folder = ((arr[13].sub "Content-location: ","").sub "/V2/","").sub "/shared-params.xml",""
        shared_params_data   = get_data(shared_params_url)
        shared_params_data   = process_sharedparams(shared_params_data)
        hash = OpenSSL::Digest::SHA512.digest(shared_params_data)
        shared_params_hash = Base64.encode64(hash)
        shared_params_hash = shared_params_hash.gsub "\n",""
        arr[6]  = "Expire-date: 2023-12-18T01:20:01Z";
        arr[13] = "Content-location: /V2_/" + shared_params_folder + "/shared-params.xml"
        arr[16] = shared_params_hash
        arr[22] = "Verification-certificate-hash: " + key_hash + '; hash-algorithm-id="http://www.w3.org/2001/04/xmlenc#sha512"';
        signedData = ""
        for i in 5..17 do
          if i<17
             signedData += arr[i] + ("\n")
          else
             signedData += arr[i]
          end
        end
        key_private = OpenSSL::PKey.read File.read '/etc/xroad/ssl/internal.key'
        digest      = OpenSSL::Digest::SHA512.new
        signature   = key_private.sign digest, signedData
        signature64 = Base64.encode64(signature)
        arr[24] = signature64;
        if key_private.verify digest, signature, signedData
          ok = 'Valid'
        else
          ok 'Invalid'
        end
        externalconf_data = "";
        for element in arr
         externalconf_data += element + ("\n")
        end
        File.open("/var/lib/xroad/public/externalconf_"+instance,"w"){
                                                                     |f| f.write externalconf_data
                                                                      f.chmod(0755)
                                                                    }
        path_v2 = "/var/lib/xroad/public/V2_/"
        FileUtils.mkdir_p path_v2
        FileUtils.chmod(0755, path_v2)

        path_v2_serial = path_v2 + "/" + shared_params_folder
        FileUtils.mkdir_p path_v2_serial
        FileUtils.chmod(0755, path_v2_serial)


        shared_params_pathname = path_v2_serial + '/shared-params.xml'
        File.open(shared_params_pathname, "w"){
                                               |f| f.write shared_params_data
                                               f.chmod(0755)
                                             }

        new_anchor_data = arr_anchor.join("\n")
  end

  def update
   count = Dir.glob("/var/lib/xroad/public/V2_/*").length
    if count >= 6
    	FileUtils.rm_rf("/var/lib/xroad/public/V2_")
    end

    list = Dir.glob("/var/lib/xroad/public/anchors/*.xml")
      for i in list do
        edit_anchor(File.read i)
      end
  end

  def update_subsystems
    #verifica cada cuanto se realiza la actualización de subsistemas
    t    =  0
    tmax = 10
    path_main ="/var/lib/xroad/public/"
    if File.exist?(path_main + "tmax")
      s    = File.read (path_main + "tmax")
      tmax = s.to_i
    end
    if File.exist?(path_main + "last_update")
      s  = File.read(path_main + "last_update")
      t = (Time.now - Time.parse(s))/60
    else
      t = 100
    end

    if t>tmax
      update
      File.open(path_main + "last_update", "w"){
                                                |f| f.write Time.now
                                                 f.chmod(0755)
                                               }
    end
  end



end
