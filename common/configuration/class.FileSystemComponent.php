<?php

error_reporting(E_ALL);

/**
 * Generis Object Oriented API -
 *
 * $Id$
 *
 * This file is part of Generis Object Oriented API.
 *
 * Automatically generated on 18.07.2012, 10:10:48 with ArgoUML PHP module 
 * (last revised $Date: 2010-01-12 20:14:42 +0100 (Tue, 12 Jan 2010) $)
 *
 * @author Jerome Bogaerts, <jerome.bogaerts@tudor.lu>
 * @package common
 * @subpackage configuration
 */

if (0 > version_compare(PHP_VERSION, '5')) {
    die('This file was generated for PHP 5');
}

/**
 * include common_configuration_Component
 *
 * @author Jerome Bogaerts, <jerome.bogaerts@tudor.lu>
 */
require_once('common/configuration/class.Component.php');

/* user defined includes */
// section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001AD3-includes begin
// section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001AD3-includes end

/* user defined constants */
// section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001AD3-constants begin
// section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001AD3-constants end

/**
 * Short description of class common_configuration_FileSystemComponent
 *
 * @access public
 * @author Jerome Bogaerts, <jerome.bogaerts@tudor.lu>
 * @package common
 * @subpackage configuration
 */
class common_configuration_FileSystemComponent
    extends common_configuration_Component
{
    // --- ASSOCIATIONS ---


    // --- ATTRIBUTES ---

    /**
     * Short description of attribute location
     *
     * @access private
     * @var string
     */
    private $location = '';

    /**
     * Short description of attribute expectedRights
     *
     * @access private
     * @var string
     */
    private $expectedRights = '';

    // --- OPERATIONS ---

    /**
     * Short description of method __construct
     *
     * @access public
     * @author Jerome Bogaerts, <jerome.bogaerts@tudor.lu>
     * @param  string location
     * @param  string expectedRights
     * @param  string name
     * @param  boolean optional
     * @return mixed
     */
    public function __construct($location, $expectedRights, $name = 'unknown', $optional = false)
    {
        // section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001B11 begin
        parent::__construct($name, $optional);
        $this->setExpectedRights($expectedRights);
        $this->setLocation($location);
        // section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001B11 end
    }

    /**
     * Short description of method getLocation
     *
     * @access public
     * @author Jerome Bogaerts, <jerome.bogaerts@tudor.lu>
     * @return string
     */
    public function getLocation()
    {
        $returnValue = (string) '';

        // section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001B1D begin
        $returnValue = $this->location;
        // section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001B1D end

        return (string) $returnValue;
    }

    /**
     * Short description of method setLocation
     *
     * @access public
     * @author Jerome Bogaerts, <jerome.bogaerts@tudor.lu>
     * @param  string location
     * @return void
     */
    public function setLocation($location)
    {
        // section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001B1F begin
        $this->location = $location;
        // section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001B1F end
    }

    /**
     * Short description of method exists
     *
     * @access public
     * @author Jerome Bogaerts, <jerome.bogaerts@tudor.lu>
     * @return boolean
     */
    public function exists()
    {
        $returnValue = (bool) false;

        // section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001B22 begin
        $returnValue = @file_exists($this->getLocation());
        // section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001B22 end

        return (bool) $returnValue;
    }

    /**
     * Short description of method getExpectedRights
     *
     * @access public
     * @author Jerome Bogaerts, <jerome.bogaerts@tudor.lu>
     * @return string
     */
    public function getExpectedRights()
    {
        $returnValue = (string) '';

        // section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001B27 begin
        $returnValue = $this->expectedRights;
        // section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001B27 end

        return (string) $returnValue;
    }

    /**
     * Short description of method setExpectedRights
     *
     * @access public
     * @author Jerome Bogaerts, <jerome.bogaerts@tudor.lu>
     * @param  string expectedRights
     * @return void
     */
    public function setExpectedRights($expectedRights)
    {
        // section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001B29 begin
        if (!empty($expectedRights) && preg_match('/^r*w*x*$/', $expectedRights) !== 0){
            $this->expectedRights = $expectedRights;    
        }
        else{
            throw new common_configuration_MalformedRightsException("Malformed rights. Expected format is r|rw|rwx.");
        }
        // section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001B29 end
    }

    /**
     * Short description of method check
     *
     * @access public
     * @author Jerome Bogaerts, <jerome.bogaerts@tudor.lu>
     * @return common_configuration_Report
     */
    public function check()
    {
        $returnValue = null;

        // section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001B95 begin
        $expectedRights = $this->getExpectedRights();
        $location = $this->getLocation();
        $name = $this->getName();
        
        if (!$this->exists()){
            return new common_configuration_Report(common_configuration_Report::UNKNOWN,
                                                   "File system component '${name}' could not be found.",
                                                   $this);
        }
        else{
            if (strpos($expectedRights, 'r') !== false && !is_readable($location)){
                return new common_configuration_Report(common_configuration_Report::INVALID,
                                                       "File system component '${name}' is not readable.",
                                                       $this);
            }
            
            if (strpos($expectedRights, 'w') !== false && !is_writable($location)){
                return new common_configuration_Report(common_configuration_Report::INVALID,
                                                       "File system component '${name}' is not writable.",
                                                       $this);
            }

            if (strpos($expectedRights, 'x') !== false && !is_executable($location)){
                return new common_configuration_Report(common_configuration_Report::INVALID,
                                                       "File system component '${name}' is not executable.",
                                                       $this);
            }
            
            return new common_configuration_Report(common_configuration_Report::VALID,
                                                   "File system component '${name}' is compliant with expected rights (${expectedRights}).'",
                                                   $this);
        } 
        // section -64--88-56-1--548fa03:1387a8a40e2:-8000:0000000000001B95 end

        return $returnValue;
    }

    /**
     * Short description of method isReadable
     *
     * @access public
     * @author Jerome Bogaerts, <jerome.bogaerts@tudor.lu>
     * @return boolean
     */
    public function isReadable()
    {
        $returnValue = (bool) false;

        // section -64--88-56-1--47c93c5c:1389911de50:-8000:0000000000001B1B begin
        $returnValue = @is_readable($this->getLocation());
        // section -64--88-56-1--47c93c5c:1389911de50:-8000:0000000000001B1B end

        return (bool) $returnValue;
    }

    /**
     * Short description of method isWritable
     *
     * @access public
     * @author Jerome Bogaerts, <jerome.bogaerts@tudor.lu>
     * @return boolean
     */
    public function isWritable()
    {
        $returnValue = (bool) false;

        // section -64--88-56-1--47c93c5c:1389911de50:-8000:0000000000001B1D begin
        $returnValue = @is_writable($this->getLocation());
        // section -64--88-56-1--47c93c5c:1389911de50:-8000:0000000000001B1D end

        return (bool) $returnValue;
    }

    /**
     * Short description of method isExecutable
     *
     * @access public
     * @author Jerome Bogaerts, <jerome.bogaerts@tudor.lu>
     * @return boolean
     */
    public function isExecutable()
    {
        $returnValue = (bool) false;

        // section -64--88-56-1--47c93c5c:1389911de50:-8000:0000000000001B1F begin
        $returnValue = @is_executable($this->getLocation());
        // section -64--88-56-1--47c93c5c:1389911de50:-8000:0000000000001B1F end

        return (bool) $returnValue;
    }

} /* end of class common_configuration_FileSystemComponent */

?>