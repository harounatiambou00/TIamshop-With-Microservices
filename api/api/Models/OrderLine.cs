namespace api.Models
{
    public class OrderLine
    {
        public long OrderLineId { get; set; }
        public int Quantity { get; set; } = 1;
        public float DiscountPercentage { get; set; } = 0;

        public long OrderId { get; set; }
        public Guid ProductId { get; set; }
    }
}
