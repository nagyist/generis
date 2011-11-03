<?php

error_reporting(E_ALL);

/**
 * Generis Object Oriented API - core/kernel/versioning/class.Repository.php
 *
 * $Id$
 *
 * This file is part of Generis Object Oriented API.
 *
 * Automatically generated on 21.10.2011, 16:17:46 with ArgoUML PHP module 
 * (last revised $Date: 2010-01-12 20:14:42 +0100 (Tue, 12 Jan 2010) $)
 *
 * @author Cédric Alfonsi, <cedric.alfonsi@tudor.lu>
 * @package core
 * @subpackage kernel_versioning
 */

if (0 > version_compare(PHP_VERSION, '5')) {
    die('This file was generated for PHP 5');
}

/**
 * Resource implements rdf:resource container identified by an uri (a string).
 * Methods enable meta data management for this resource
 *
 * @author patrick.plichart@tudor.lu
 * @see http://www.w3.org/RDF/
 * @version v1.0
 */
require_once('core/kernel/classes/class.Resource.php');

/**
 * include core_kernel_versioning_RepositoryProxy
 *
 * @author Cédric Alfonsi, <cedric.alfonsi@tudor.lu>
 */
require_once('core/kernel/versioning/class.RepositoryProxy.php');

/* user defined includes */
// section 127-0-1-1--548d6005:132d344931b:-8000:0000000000002519-includes begin
// section 127-0-1-1--548d6005:132d344931b:-8000:0000000000002519-includes end

/* user defined constants */
// section 127-0-1-1--548d6005:132d344931b:-8000:0000000000002519-constants begin
// section 127-0-1-1--548d6005:132d344931b:-8000:0000000000002519-constants end

/**
 * Short description of class core_kernel_versioning_Repository
 *
 * @access public
 * @author Cédric Alfonsi, <cedric.alfonsi@tudor.lu>
 * @package core
 * @subpackage kernel_versioning
 */
class core_kernel_versioning_Repository
    extends core_kernel_classes_Resource
{
    // --- ASSOCIATIONS ---


    // --- ATTRIBUTES ---

    /**
     * Short description of attribute authenticated
     *
     * @access private
     * @var boolean
     */
    private $authenticated = false;

    // --- OPERATIONS ---

    /**
     * Repository factory
     *
     * @access public
     * @author Cédric Alfonsi, <cedric.alfonsi@tudor.lu>
     * @param  Resource type
     * @param  string url
     * @param  string login
     * @param  string password
     * @param  string path
     * @param  string label
     * @param  string comment
     * @param  string uri
     * @return core_kernel_versioning_subversion_Repository
     */
    public static function create( core_kernel_classes_Resource $type, $url, $login, $password, $path, $label, $comment, $uri = '')
    {
        $returnValue = null;

        // section 127-0-1-1--548d6005:132d344931b:-8000:000000000000251D begin
        
        //var_dump(debug_backtrace());
        
        $versioningRepositoryClass = new core_kernel_classes_Class(CLASS_GENERIS_VERSIONEDREPOSITORY);
        
        $repository = $versioningRepositoryClass->createInstance($label, $comment, $uri);
		
        $versioningRepositoryUrlProp = new core_kernel_classes_Property(PROPERTY_GENERIS_VERSIONEDREPOSITORY_URL);
		$repository->setPropertyValue($versioningRepositoryUrlProp, $url);
		
		$versioningRepositoryPathProp = new core_kernel_classes_Property(PROPERTY_GENERIS_VERSIONEDREPOSITORY_PATH);
		$repository->setPropertyValue($versioningRepositoryPathProp, $path);
		
		$versioningRepositoryTypeProp = new core_kernel_classes_Property(PROPERTY_GENERIS_VERSIONEDREPOSITORY_TYPE);
		$repository->setPropertyValue($versioningRepositoryTypeProp, $type);
		
		$versioningRepositoryLoginProp = new core_kernel_classes_Property(PROPERTY_GENERIS_VERSIONEDREPOSITORY_LOGIN);
		$repository->setPropertyValue($versioningRepositoryLoginProp, $login);
		
		$versioningRepositoryPasswordProp = new core_kernel_classes_Property(PROPERTY_GENERIS_VERSIONEDREPOSITORY_PASSWORD);
		$repository->setPropertyValue($versioningRepositoryPasswordProp, $password);
		
		$returnValue = new core_kernel_versioning_Repository($repository->uriResource);
		
        // section 127-0-1-1--548d6005:132d344931b:-8000:000000000000251D end

        return $returnValue;
    }

    /**
     * Checkout the remote repository to a local directory
     *
     * @access public
     * @author Cédric Alfonsi, <cedric.alfonsi@tudor.lu>
     * @param  int revision
     * @return boolean
     */
    public function checkout($revision = null)
    {
        $returnValue = (bool) false;

        // section 127-0-1-1--548d6005:132d344931b:-8000:000000000000251A begin
		
        $VersioningRepositoryUrlProp = new core_kernel_classes_Property(PROPERTY_GENERIS_VERSIONEDREPOSITORY_URL);
		$url = (string)$this->getOnePropertyValue($VersioningRepositoryUrlProp);
		
		$VersioningRepositoryPathProp = new core_kernel_classes_Property(PROPERTY_GENERIS_VERSIONEDREPOSITORY_PATH);
		$path = (string)$this->getOnePropertyValue($VersioningRepositoryPathProp);
		
        if ($this->authenticate()){
        	$returnValue = core_kernel_versioning_RepositoryProxy::singleton()->checkout($this, $url, $path, $revision);
        }
        
        // section 127-0-1-1--548d6005:132d344931b:-8000:000000000000251A end

        return (bool) $returnValue;
    }

    /**
     * Get the repository type
     *
     * @access public
     * @author Cédric Alfonsi, <cedric.alfonsi@tudor.lu>
     * @return core_kernel_classes_Resource
     */
    public function getType()
    {
        $returnValue = null;

        // section 127-0-1-1-13a27439:132dd89c261:-8000:00000000000016D7 begin
        
        $returnValue = $this->getOnePropertyValue(new core_kernel_classes_Property(PROPERTY_GENERIS_VERSIONEDREPOSITORY_TYPE));

        // section 127-0-1-1-13a27439:132dd89c261:-8000:00000000000016D7 end

        return $returnValue;
    }

    /**
     * Get path of the local repository
     *
     * @access public
     * @author Cédric Alfonsi, <cedric.alfonsi@tudor.lu>
     * @return string
     */
    public function getPath()
    {
        $returnValue = (string) '';

        // section 127-0-1-1-13a27439:132dd89c261:-8000:00000000000016D9 begin
        
        $returnValue = $this->getOnePropertyValue(new core_kernel_classes_Property(PROPERTY_GENERIS_VERSIONEDREPOSITORY_PATH));
        
        // section 127-0-1-1-13a27439:132dd89c261:-8000:00000000000016D9 end

        return (string) $returnValue;
    }

    /**
     * Get authenticated with the remote repository
     *
     * @access public
     * @author Cédric Alfonsi, <cedric.alfonsi@tudor.lu>
     * @return boolean
     */
    public function authenticate()
    {
        $returnValue = (bool) false;

        // section 127-0-1-1-13a27439:132dd89c261:-8000:00000000000016EB begin
        
        if($this->authenticated){
        	
        	$returnValue = true;
        } else {
        	
	        $VersioningRepositoryTypeProp = new core_kernel_classes_Property(PROPERTY_GENERIS_VERSIONEDREPOSITORY_LOGIN);
			$login = (string)$this->getOnePropertyValue($VersioningRepositoryTypeProp);
			
			$VersioningRepositoryTypeProp = new core_kernel_classes_Property(PROPERTY_GENERIS_VERSIONEDREPOSITORY_PASSWORD);
			$password = (string)$this->getOnePropertyValue($VersioningRepositoryTypeProp); 
			
			$returnValue = $this->authenticated = core_kernel_versioning_RepositoryProxy::singleton()->authenticate($this, $login, $password);
        }
		
        // section 127-0-1-1-13a27439:132dd89c261:-8000:00000000000016EB end

        return (bool) $returnValue;
    }

    /**
     * Delete the repository.
     * Be carrefull, the function does not delete the directory in the file 
     * system.
     *
     * @access public
     * @author Cédric Alfonsi, <cedric.alfonsi@tudor.lu>
     * @return boolean
     */
    public function delete()
    {
        $returnValue = (bool) false;

        // section 127-0-1-1--57fd8084:132ecf4b934:-8000:00000000000016F7 begin
        
        $path = $this->getPath();
        if(is_dir($path)){
        	// Remove the local directory
        	//var_dump('DETELETE repo');
        	//tao_helpers_File::remove($path, true);
        	$returnValue = parent::delete(true);
        }
        
        // section 127-0-1-1--57fd8084:132ecf4b934:-8000:00000000000016F7 end

        return (bool) $returnValue;
    }

} /* end of class core_kernel_versioning_Repository */

?>