<?php
/**
 * This class contains some helpers in order to facilitate the creation of complex tests
 *
 * @author Joel Bout, <taosupport@tudor.lu>
 * @author Jehan Bihin
 * @package ClearFw
 * @subpackage core
 * @subpackage helpers
 */


class TestCasePrototype extends UnitTestCase {

	private $files = array();

	/**
	 * Create a new temporary file
	 * @param string $pContent
	 */
	public function createFile($pContent = '', $name = null) {
		if (is_null($name)) $tmpfname = tempnam(sys_get_temp_dir(), "tst");
		else $tmpfname = sys_get_temp_dir().$name;
		$this->files[] = $tmpfname;

		if (!empty($pContent)) {
			$handle = fopen($tmpfname, "w");
			fwrite($handle, $pContent);
			fclose($handle);
		}

		return $tmpfname;
	}

	/**
	 * Cleanup of files
	 * @see SimpleTestCase::after()
	 */
	public function after($method) {
		parent::after($method);
		foreach ($this->files as $file) {
			@unlink($file);
		}
		$this->files = array();
	}

}