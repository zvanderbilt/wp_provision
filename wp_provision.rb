#!/usr/bin/env ruby

require 'optparse'
require 'fileutils'
require 'pp'
require 'find'
require 'wpcli'
require 'mysql2'
require 'csv'
require 'uri'
require 'highline/import'
require 'etc'

class ProvisionParser

Version = 0.2

  def self.parse(args)
      options = {
          domain: 'testing.localhost',
          dest_dir: '/tmp/',
          email: 'root@kiosk.tm',
          admin_user: 'superadmin'
      }

      opts = OptionParser.new do |opts|
          opts.banner = "Usage: #$0 [options]"
          opts.separator ""
          opts.separator "Specific options:"

          # Destination for new wp install 
          opts.on("-d", "--dest [DESTINATION]", "WordPress Install Destination") do |dest|
              options[:dest] = dest
          end

          # base path
          opts.on("-p", "--path [PATH]", "Optional Base Path to installation") do |path|
              options[:path] = path
          end

          # base url
          opts.on("-u", "--url [URL]", "Fully Qualified Domain Name") do |url|
              options[:url] = url
          end

          # multisite switch
          opts.on("-m", "--multisite [MULTISITE]", "Switch for multisite network") do |multisite|
              options[:multisite] = multisite
          end
   
          # Database name
          opts.on("-w", "--dbname [DBNAME]", "Database name") do |dbname|
              options[:dbname] = dbname
          end

          # Database host
          opts.on("-x", "--host [DBHOST]", "Fully Qualified Domain Name or IP") do |host|
              options[:host] = host
          end

          # Database user
          opts.on("-y", "--dbuser [DBUSER]", "Database Username to be created") do |dbuser|
              options[:dbuser] = dbuser
          end

          # Database pass
          opts.on("-z", "--dbpass [DBPASS]", "Hashed password to be used in new database") do |dbpass|
              options[:dbpass] = dbpass
          end

          # wp admin user
          opts.on("-u", "--wpuser [WPUSER]", "Admin Username to be created") do |wpuser|
              options[:wpuser] = wpuser
          end

          # admin email
          opts.on("-e", "--email [EMAIL]", "Admin email address to be used") do |email|
              options[:email] = email
          end

          # admin email
          opts.on("-c", "--vhostdir [/etc/httpd/vhost.d/]", "VirtualHost configuration directory") do |vhostdir|
              options[:vhostdir] = vhostdir
          end

          # Boolean switch.
          opts.on("-v", "--[no-]verbose", "Run verbosely") do |v|
              options[:verbose] = v
          end

          opts.separator ""
          opts.separator "Common options:"

          # No argument, shows at tail.  This will print an options summary.
          opts.on_tail("-h", "--help", "Show this message") do
              puts opts
              exit
          end

          opts.on_tail("-V", "--version", "Show version") do
              puts Version
              exit
          end
      end

  opts.parse!
  options

  end  # parse
end  # class ProvsionParser

class Creator

def initialize(options)
    @options = options 
end

def as_user(user, &block)
    u = Etc.getpwnam(user)
    Process.fork do
        Process.uid = u.uid
        block.call(user)
    end
end

def create_database(options)
    @db_host = 'localhost'
    @login_user = 'root'

    @login_pass = ask("Enter password for mysql root user: ") { |q| q.echo = false }

    STDOUT.sync = true
    puts "\nDatabase name:"
    	@db_name = options[:dbname]
    puts "\nDatabase username:"
   	 @db_user = options[:dbuser]
    puts "\nDatabase user password:"
    	@db_pass = options[:dbpass]

    client = Mysql2::Client.new(:host => @db_host,
                                :username => @login_user,
                                :password => @login_pass)
    client.query("CREATE DATABASE #{@db_name};")
    client.query("GRANT ALL PRIVILEGES ON #{@db_name}.* TO #{@db_user}@#{@db_host} IDENTIFIED BY '#{@db_pass}';")
    client.query("FLUSH PRIVILEGES;")
    client.close
end


def scaffold_wp(options)
    FileUtils.mkdir_p(options[:dest])
    create_database(options)
    Dir.chdir(options[:dest])
    FileUtils.chown_R 'www-data', 'www-data', options[:dest]
    FileUtils.chmod  'g+s', options[:dest]
    as_user "www-data" do |user|
        @wpcli = Wpcli::Client.new options[:dest]
        @wpcli.run "core download --allow-root"
        @wpcli.run "core config --dbname=#{options[:dbname]} --dbuser=#{options[:dbuser]} --dbpass=#{options[:dbpass]} --skip-check --allow-root" 
        @wpcli.run "core install --url=#{options[:url]} --admin_user=#{options[:wpuser]} --admin_email=#{options[:email]} --title=somesite --allow-root"
        @wpcli.run "plugin install akismet wordfence ewww-image-optimizer email-address-encoder simple-history use-google-libraries wordpress-seo wp2syslog --activate --allow-root"
        @wpcli.run "plugin install w3-total-cache --allow-root"
        @wpcli.run "role create supereditor SuperEditor --clone=editor --allow-root"
        @wpcli.run "cap add 'supereditor' 'manage_options' --allow-root"
	@wpcli.run "rewrite flush --hard"
    	customize_wp(options)
    end 
end

def customize_wp(options)
    File.write(f = "./wp-config.php", File.read(f).gsub(/table_prefix = 'wp_';/,"table_prefix = 'wp_';\n\ndefine( 'WP_DEBUG', true );\ndefine( 'WP_DEBUG_DISPLAY', false );\ndefine( 'WP_DEBUG_LOG', true );"))
    File.write(f = "./wp-config.php", File.read(f).gsub(/<\?php/,"<?php\n\ndefine('DISALLOW_FILE_EDIT', true);\ndefine('WP_HOME', '#{options[:url]}');\ndefine('WP_SITEURL', '#{options[:url]}');\ndefine('FS_CHMOD_FILE', 0660);\ndefine('FS_CHMOD_DIR', 0775);\n"))
   end  
end

end # class Creator 

### EXECUTE ###
begin
    options = ProvisionParser.parse(ARGV)

    if options[:verbose]
        pp options 
    else	
        options
    end

    Creator.new(options).scaffold_wp(options)
rescue => e
    puts e
end
