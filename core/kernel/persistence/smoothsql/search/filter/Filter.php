<?php

namespace oat\generis\model\kernel\persistence\smoothsql\search\filter;

/**
 * @deprecated As we have multiple persistence implementation now please use
 * \oat\generis\model\kernel\persistence\Filter::class as more generic filter implementation
 */
class Filter extends \oat\generis\model\kernel\persistence\Filter
{
    /**
     * @param string $key
     * @param string $value
     * @param FilterOperator $operator
     * @param array $orConditionValues
     * @internal param array $inOrConditionValues
     */
    public function __construct($key, $value, FilterOperator $operator, array $orConditionValues = [])
    {
        parent::__construct(
            $key,
            $value,
            $operator->getValue(),
            $orConditionValues
        );
    }
}
