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

require 'fileutils'
require 'net/http'
require 'socket'
require 'digest'
require 'base64'
require 'openssl'

java_import Java::ee.ria.xroad.common.SystemProperties
java_import Java::ee.ria.xroad.common.util.CryptoUtils
java_import Java::ee.ria.xroad.common.util.HashCalculator
java_import Java::ee.ria.xroad.commonui.SignerProxy

class ConfigurationManagementController < ApplicationController
  UPLOAD_FILE_HASH_ALGORITHM = CryptoUtils::SHA224_ID

  before_filter :verify_get, :only => [
    :index,
    :source,
    :available_tokens,
    :download_conf_part,
    :trusted_anchors,
    :can_view_trusted_anchors
  ]

  before_filter :verify_post, :only => [
    :generate_source_anchor,
    :generate_signing_key,
    :activate_signing_key,
    :delete_signing_key,
    :logout_token,
    :upload_conf_part,
    :upload_trusted_anchor,
    :save_uploaded_trusted_anchor,
    :clear_uploaded_trusted_anchor,
    :delete_trusted_anchor
  ]

  upload_callbacks({
    :upload_conf_part => "XROAD_CONFIGURATION_SOURCE.uploadCallback",
    :upload_trusted_anchor => "XROAD_TRUSTED_ANCHORS.uploadCallback"
  })

  # -- Common GET methods - start ---

  def index
    authorize!(:view_configuration_management)
  end

  # -- Common GET methods - end ---

  # -- Specific GET methods - start ---

  def source
    validate_params({
      :source_type => [:required]
    })

    if params[:source_type] == ConfigurationSource::SOURCE_TYPE_INTERNAL
      authorize!(:view_internal_configuration_source)
    elsif params[:source_type] == ConfigurationSource::SOURCE_TYPE_EXTERNAL
      authorize!(:view_external_configuration_source)
    else
      raise "Unknown source type"
    end

    source = ConfigurationSource.get_source_by_type(params[:source_type])

    render_source(source)
  end

  def download_source_anchor
    authorize!(:download_source_anchor)

    validate_params({
      :source_type => [:required]
    })

    source = ConfigurationSource.get_source_by_type(params[:source_type])

    raise "Anchor not found" unless source.anchor_file

    if params[:source_type]=="internal"
       anchor = source.anchor_file
    else
       anchor = edit_anchor(source.anchor_file)
    end

    send_data(anchor, :filename =>
      get_anchor_filename(
        SystemParameter.instance_identifier,
        source.source_type,
        source.anchor_generated_at))
  end

  def available_tokens
    authorize!(:generate_signing_key)

    validate_params

    tokens = []

    SignerProxy::getTokens.each do |token|
      tokens << {
        :id => token.id,
        :label => token.friendlyName || token.id,
        :inactive => !token.active
      } if token.available
    end

    render_json(tokens)
  end

  def download_conf_part
    authorize!(:download_configuration_part)

    validate_params({
      :content_identifier => [:required],
      :version => [:required]
    })

    conf_part = DistributedFiles.get_by_content_id_and_version(params[:content_identifier], params[:version])
    file_name = conf_part.file_name
    ext = File.extname(file_name)
    file_name[ext] = "_" +
      format_time(conf_part.file_updated_at.localtime).gsub(" ", "_") + ext

    send_data(conf_part.file_data, :filename => file_name)
  end

  def trusted_anchors
    authorize!(:view_trusted_anchors)

    can_delete = can?(:delete_trusted_anchor)
    can_download = can?(:download_trusted_anchor)

    result = []

    TrustedAnchor.find_each do |each|
      generated_at = each.generated_at != nil ?
        format_time(each.generated_at, true): "N/A"

      result << {
          :id => each.id,
          :instance_identifier => each.instance_identifier,
          :hash => each.trusted_anchor_hash,
          :generated_at => generated_at,
          :can_delete => can_delete,
          :can_download => can_download
      }
    end

    render_json_without_messages(result)
  end

  def download_trusted_anchor
    authorize!(:download_trusted_anchor)

    validate_params({
      :id => [:required]
    })

    anchor = TrustedAnchor.find(params[:id])
    raise "Anchor not found" unless anchor

    send_data(anchor.trusted_anchor_file, :filename =>
      get_anchor_filename(
        anchor.instance_identifier,
        ConfigurationSource::SOURCE_TYPE_EXTERNAL,
        anchor.generated_at))
  end

  def can_view_trusted_anchors
    render_json({:can => can?(:view_trusted_anchors)})
  end

  # -- Specific GET methods - end ---

  # -- Specific POST methods - start ---

  def generate_source_anchor
    if params[:source_type] == ConfigurationSource::SOURCE_TYPE_INTERNAL
      audit_log("Re-create internal configuration anchor", audit_log_data = {})
    else
      audit_log("Re-create external configuration anchor", audit_log_data = {})
    end

    authorize!(:generate_source_anchor)

    validate_params({
      :source_type => [:required]
    })

    source = ConfigurationSource.get_source_by_type(params[:source_type])

    unless source
      raise "Configuration source not found"
    end

    source.generate_anchor

    audit_log_data[:anchorFileHash] = source.anchor_file_hash
    audit_log_data[:anchorFileHashAlgorithm] =
      ConfigurationSource::ANCHOR_FILE_HASH_ALGORITHM

    notice(t("configuration_management.sources." \
             "#{source.source_type}_anchor_generated"))

    render_source(source)
  end

  def generate_signing_key
    if params[:source_type] == ConfigurationSource::SOURCE_TYPE_INTERNAL
      audit_log("Generate internal configuration signing key",
        audit_log_data = {})
    else
      audit_log("Generate external configuration signing key",
        audit_log_data = {})
    end

    authorize!(:generate_signing_key)

    validate_params({
      :source_type => [:required],
      :token_id => [:required],
      :label => []
    })

    token = SignerProxy::getToken(params[:token_id])

    audit_log_data[:tokenId] = token.id
    audit_log_data[:tokenSerialNumber] = token.serialNumber
    audit_log_data[:tokenFriendlyName] = token.friendlyName

    source = ConfigurationSource.get_source_by_type(params[:source_type])

    signing_key = source.generate_signing_key(params[:token_id], params[:label])

    audit_log_data[:keyId] = signing_key.key_identifier
    audit_log_data[:keyLabel] = params[:label]
    audit_log_data[:certHash] =
      CommonUi::CertUtils.cert_hash(signing_key.cert)
    audit_log_data[:certHashAlgorithm] =
      CommonUi::CertUtils.cert_hash_algorithm

    begin
      source.generate_anchor
      notice(t("configuration_management.sources." \
        "#{source.source_type}_anchor_generated"))
    rescue
      error(t("configuration_management.sources." \
        "#{source.source_type}_anchor_error", :reason => $!.message))
    end

    render_source(source)
  end

  def activate_signing_key
    if params[:source_type] == ConfigurationSource::SOURCE_TYPE_INTERNAL
      audit_log("Activate internal configuration signing key",
        audit_log_data = {})
    else
      audit_log("Activate external configuration signing key",
        audit_log_data = {})
    end

    authorize!(:activate_signing_key)

    validate_params({
      :source_type => [:required],
      :id => [:required]
    })

    key = ConfigurationSigningKey.find(params[:id])

    # Only activate available keys
    token = SignerProxy::getToken(key.token_identifier)

    audit_log_data[:tokenId] = token.id
    audit_log_data[:tokenSerialNumber] = token.serialNumber
    audit_log_data[:tokenFriendlyName] = token.friendlyName
    audit_log_data[:keyId] = key.key_identifier

    token.keyInfo.each do |key_info|
      if key_info.id == key.key_identifier
        if !token.available || !key_info.available
          raise t("configuration_management.sources.token_or_key_not_available")
        end

        break
      end
    end

    key.configuration_source.update_attributes!({
      :active_key => key
    })

    render_source(key.configuration_source)
  end

  def delete_signing_key
    if params[:source_type] == ConfigurationSource::SOURCE_TYPE_INTERNAL
      audit_log("Delete internal configuration signing key",
        audit_log_data = {})
    else
      audit_log("Delete external configuration signing key",
        audit_log_data = {})
    end

    authorize!(:delete_signing_key)

    validate_params({
      :source_type => [:required],
      :id => [:required]
    })

    key = ConfigurationSigningKey.find(params[:id])

    audit_log_data[:tokenId] = key.token_identifier
    audit_log_data[:keyId] = key.key_identifier

    key.destroy

    notice(t("configuration_management.sources.deleting_key_from_conf_success"))

    begin
      token = SignerProxy::getToken(key.token_identifier)
      token_name = (token && token.friendlyName) || key.token_identifier

      audit_log_data[:tokenSerialNumber] = token.serialNumber
      audit_log_data[:tokenFriendlyName] = token.friendlyName

      translate_coded_exception do
        SignerProxy::deleteKey(key.key_identifier, true)
      end

      notice!(t("configuration_management.sources.deleting_key_from_token_success", {
        :token => token_name
      }))
    rescue
      error(t("configuration_management.sources.deleting_key_from_token_failed", {
        :token => token_name,
        :reason => $!.message
      }))
    end

    source = key.configuration_source

    begin
      source.generate_anchor
      notice(t("configuration_management.sources." \
        "#{source.source_type}_anchor_generated"))
    rescue
      error(t("configuration_management.sources." \
        "#{source.source_type}_anchor_error", :reason => $!.message))
    end

    render_source(key.configuration_source)
  end

  def upload_conf_part
    audit_log("Upload configuration part", audit_log_data = {})

    authorize!(:upload_configuration_part)

    validate_params({
      :source_type => [:required],
      :content_identifier => [:required],
      :file_upload => [:required],
      :part_file_name => [:required]
    })

    content_identifier = params[:content_identifier]
    upload_file_name = params[:file_upload].original_filename
    file_name = params[:part_file_name]

    audit_log_data[:sourceType] = params[:source_type]
    audit_log_data[:contentIdentifier] = content_identifier
    audit_log_data[:partFileName] = file_name
    audit_log_data[:uploadFileName] = upload_file_name

    source = ConfigurationSource.get_source_by_type(params[:source_type])

    source_type = source.source_type

    if source_type == ConfigurationSource::SOURCE_TYPE_EXTERNAL &&
        content_identifier != DistributedFiles::CONTENT_IDENTIFIER_SHARED_PARAMS
      raise "Unknown configuration part"
    end

    optional_parts_conf = DistributedFiles.get_optional_parts_conf()

    validation_program =
        optional_parts_conf.getValidationProgram(file_name)

    file_bytes = params[:file_upload].read
    file_hash = CryptoUtils::hexDigest(UPLOAD_FILE_HASH_ALGORITHM,
        file_bytes.to_java_bytes)

    audit_log_data[:uploadFileHash] = file_hash
    audit_log_data[:uploadFileHashAlgorithm] = UPLOAD_FILE_HASH_ALGORITHM

    file_validator = OptionalConfParts::Validator.new(
        validation_program, file_bytes, content_identifier)

    validator_stderr = file_validator.validate()

    DistributedFiles.lookup_and_save_configuration_part(file_name , file_bytes)

    notice(get_uploaded_message(validator_stderr, content_identifier))

    response = {
      :parts => DistributedFiles.get_configuration_parts_as_json(
          source_type, get_error_callback),
      :stderr => validator_stderr
    }

    render_json(response)
  end

  def upload_trusted_anchor
    authorize!(:upload_trusted_anchor)

    validate_params({
      :file_upload => [:required]
    })

    @temp_anchor_path = get_temp_anchor_path
   @anchor_xml = edit_anchor(params[:file_upload].read)
    @anchor_hash = get_anchor_hash

    save_temp_anchor

    # File must be saved to disk in order to use unmarshaller!
    @anchor_unmarshaller = AnchorUnmarshaller.new(@temp_anchor_path)

    render_json(get_anchor_info)
  rescue Java::ee.ria.xroad.common.CodedException => e
    log_stacktrace(e)

    logger.error("Schema validation of uploaded anchor failed, message:\n'"\
        "#{e.message}'")

    raise t("configuration_management.trusted_anchors.error.anchor_malformed")
  end

  def save_uploaded_trusted_anchor
    audit_log("Add trusted anchor", audit_log_data = {})

    authorize!(:upload_trusted_anchor)

    validate_params

    init_temp_anchor

    audit_log_data[:anchorFileHash] = @temp_anchor_hash
    audit_log_data[:anchorFileHashAlgorithm] =
      ConfigurationSource::ANCHOR_FILE_HASH_ALGORITHM

    @anchor_unmarshaller = AnchorUnmarshaller.new(@temp_anchor_path)

    audit_log_data[:instanceIdentifier] =
      @anchor_unmarshaller.get_instance_identifier
    audit_log_data[:generatedAt] =
      @anchor_unmarshaller.get_generated_at.iso8601
    audit_log_data[:anchorUrls] =
      @anchor_unmarshaller.get_anchor_urls.collect do |anchor_url|
        anchor_url.url
      end

    CommonUi::ScriptUtils.verify_external_configuration(@temp_anchor_path)

    save_anchor
    clear_temp_anchor_data

    render_json
  end

  # FUTURE Get rid of
  def clear_uploaded_trusted_anchor
    authorize!(:upload_trusted_anchor)

    @upload_cancelled = true

    clear_temp_anchor_data

    render_json_without_messages
  end

  def delete_trusted_anchor
    audit_log("Delete trusted anchor", audit_log_data = {})

    authorize!(:delete_trusted_anchor)

    validate_params({
      :id => [:required]
    })

    trusted_anchor = TrustedAnchor.find(params[:id])

    audit_log_data[:instanceIdentifier] = trusted_anchor.instance_identifier
    audit_log_data[:anchorFileHash] = trusted_anchor.trusted_anchor_hash
    audit_log_data[:anchorFileHashAlgorithm] =
      ConfigurationSource::ANCHOR_FILE_HASH_ALGORITHM

    trusted_anchor.destroy
    destroy_anchor(trusted_anchor.instance_identifier)
    notice(t("configuration_management.trusted_anchors.delete_successful",
        :instance => trusted_anchor.instance_identifier))

    render_json
  end

  # -- Specific POST methods - end ---

  private

  def render_source(source)
    source_dir =
      (params[:source_type] == ConfigurationSource::SOURCE_TYPE_INTERNAL) \
        ? SystemProperties::getCenterInternalDirectory \
        : SystemProperties::getCenterExternalDirectory

    if SystemParameter.central_server_address
      download_url = "http://#{SystemParameter.central_server_address}/#{source_dir}"
    end

    keys = {}

    source.configuration_signing_keys.find_each do |key|
      key_generation_time = key.key_generated_at != nil ?
          key.key_generated_at.localtime : nil

      keys[key.key_identifier] = {
        :id => key.id,
        :token_id => key.token_identifier,
        :token_friendly_name => key.token_identifier,
        :token_active => false,
        :token_available => false,
        :key_id => key.key_identifier,
        :key_generated_at => format_time(key_generation_time),
        :key_active => source.active_key && key.id == source.active_key.id,
        :key_available => false
      }
    end

    SignerProxy::getTokens.each do |token|
      token.keyInfo.each do |key|
        if keys.has_key?(key.id)
          keys[key.id][:token_active] = token.active
          keys[key.id][:token_available] = token.available
          keys[key.id][:key_available] =
            key.available || (token.available && !token.active)
        end
      end

      keys.each_value do |val|
        if val[:token_id] == token.id
          val[:token_friendly_name] = token.friendlyName || token.id
        end
      end
    end

    render_json({
      :anchor_file_hash => source.anchor_file_hash,
      :anchor_generated_at => format_time(source.anchor_generated_at, true),
      :download_url => download_url,
      :keys => keys.values,
      :parts => DistributedFiles.get_configuration_parts_as_json(
          source.source_type, get_error_callback)
    })
  end

  def get_uploaded_message(validator_stderr, content_identifier)
    translation_key = validator_stderr.empty? ?
        "configuration_management.sources.conf_part_upload.successful":
        "configuration_management.sources.conf_part_upload.warnings"

    return t(translation_key, :content_identifier => content_identifier)
  end

  def get_error_callback
    if params[:source_type] == ConfigurationSource::SOURCE_TYPE_INTERNAL
      ->(error_messages) do
        error_messages.each do |each|
          error(t("configuration_management.sources.optional_part_conf_error",
              :message => each))
        end
      end
    else
      nil
    end
  end

  # -- Methods related to anchor upload - start ---

  def save_temp_anchor
    raise "Temp anchor path must be present" if @temp_anchor_path.blank?
    raise "Anchor XML must be present" if @anchor_xml.blank?
    raise "Anchor hash must be present" if @anchor_hash.blank?

    CommonUi::IOUtils.write_binary(@temp_anchor_path, @anchor_xml)

    session[:anchor_temp_path] = @temp_anchor_path
    session[:anchor_hash] = @anchor_hash
  end

  def get_temp_anchor_path
    CommonUi::IOUtils.temp_file("uploaded_anchor_#{request.session_options[:id]}")
  end

  def get_anchor_hash
    raise "Anchor XML must be present" if @anchor_xml.blank?

    format_hash(CryptoUtils::hexDigest(
      ConfigurationSource::ANCHOR_FILE_HASH_ALGORITHM,
      @anchor_xml.to_java_bytes))
  end

  def get_anchor_info
    raise "Anchor hash must be present" if @anchor_hash.blank?
    raise "Anchor unmarshaller must be present" if @anchor_unmarshaller.blank?

    instance_identifier = @anchor_unmarshaller.get_instance_identifier

    if instance_identifier.eql?(SystemParameter.instance_identifier)
      raise t("configuration_management.trusted_anchors.error.same_instance")
    end

    instance_info =
        t("configuration_management.trusted_anchors.upload_info.instance",
            :instance => instance_identifier)

    generated_at = @anchor_unmarshaller.get_generated_at
    formatted_generation_time = generated_at != nil ?
        format_time(generated_at.utc, true) : "N/A"
    generated_info =
        t("configuration_management.trusted_anchors.upload_info.generated",
            :generated => formatted_generation_time)

    hash_info =
      t("configuration_management.trusted_anchors.upload_info.hash",
        :alg => ConfigurationSource::ANCHOR_FILE_HASH_ALGORITHM,
        :hash => @anchor_hash)

    {
      :instance => instance_info,
      :generated => generated_info,
      :hash => hash_info
    }
  end

  # -- Methods related to anchor upload - end ---

  # -- Methods related to saving anchor - start ---

  def init_temp_anchor
     @temp_anchor_path = session[:anchor_temp_path]
     @temp_anchor_hash = session[:anchor_hash]
  end

  def save_anchor
    anchor_hash = session[:anchor_hash]

    logger.debug("Going to save anchor from temp file '#@temp_anchor_path' "\
        "and with hash '#{anchor_hash}'")

    TrustedAnchor.add_anchor(
        AnchorUnmarshaller.new(@temp_anchor_path), @temp_anchor_hash)

    @anchor_saved = true
  end

  # -- Methods related to saving anchor - end ---

  def clear_temp_anchor_data
    clear_session_temp_anchor_data()
    clear_anchor_temp_file() if can_clear_anchor_temp_file?()
  end

  def clear_session_temp_anchor_data
    session.delete(:anchor_temp_path)
    session.delete(:anchor_hash)
  end

  def clear_anchor_temp_file
    return if @temp_anchor_path.blank?

    logger.debug("Removing anchor temp file '#@temp_anchor_path'...")

    FileUtils.rm(@temp_anchor_path);
  end

  def get_anchor_filename(instance_identifier, source_type, generated_at)
    formatted = generated_at != nil ?
        "_#{format_time(generated_at, true).gsub(" ", "_")}" : ""

    return "configuration_anchor_#{instance_identifier}_#{source_type}#{formatted}.xml"
  end

  def can_clear_anchor_temp_file?
    return @upload_cancelled || @anchor_saved
  end

  def format_hash(hash)
    return hash.upcase.scan(/.{1,2}/).join(':')
  end

  def destroy_anchor(instance)
    file_externalconf = "/var/lib/xroad/public/externalconf_" + instance + ".xml"
    file_anchor = "/var/lib/xroad/public/anchors/anchor_" + instance + ".xml"
      File.delete(file_externalconf) if File.exist?(file_externalconf)
      File.delete(file_anchor) if File.exist?(file_anchor)
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
        path_anchors = "/var/lib/xroad/public/anchors"
        FileUtils.mkdir_p path_anchors
        FileUtils.chmod(0755, path_anchors)
        File.open(path_anchors + "/anchor_" + instance + ".xml","w"){
                                                                     |f| f.write anchor
                                                                      f.chmod(0755)
                                                                    }
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

end
